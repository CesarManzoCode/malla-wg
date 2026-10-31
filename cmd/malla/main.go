// Command malla is the node of the mesh. In this version it only has
// `malla up`: in static mode the peers come from the configuration file,
// and with coord_url they come from the coordination's map.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/mesh"
	"github.com/CesarManzoCode/malla-wg/internal/runtime"
	"github.com/CesarManzoCode/malla-wg/internal/tun"
)

// mtu is the TUN's MTU, the default of wg-quick: 1500 minus 80 bytes of
// IPv6, UDP and WireGuard overhead.
const mtu = 1420

func usage() {
	fmt.Fprintln(os.Stderr, "usage: malla up -config node.json")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "up":
		fs := flag.NewFlagSet("up", flag.ExitOnError)
		path := fs.String("config", "", "node configuration file")
		fs.Parse(os.Args[2:])
		if *path == "" {
			usage()
		}
		if err := up(*path); err != nil {
			fmt.Fprintln(os.Stderr, "malla:", err)
			os.Exit(1)
		}
	default:
		usage()
	}
}

func up(path string) error {
	c, err := readConfig(path)
	if err != nil {
		return err
	}
	if c.CoordURL != "" {
		m, err := loadMesh(path, c)
		if err != nil {
			return err
		}
		return upMesh(m)
	}
	cfg, err := loadStatic(path, c)
	if err != nil {
		return err
	}
	cfg.dev.MTU = mtu
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(cfg.listenPort)})
	if err != nil {
		return err
	}
	dev, err := tun.OpenLinux(cfg.tunName)
	if err != nil {
		conn.Close()
		return err
	}
	if err := configureTUN(dev.Name(), cfg); err != nil {
		conn.Close()
		dev.Close()
		return err
	}
	node, err := runtime.New(runtime.Config{Device: cfg.dev, Conn: conn, TUN: dev, OnEvent: logEvent})
	if err != nil {
		conn.Close()
		dev.Close()
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pub := node.PublicKey()
	// The test harness waits for this line: from here on the TUN is up
	// and the socket is listening.
	fmt.Printf("malla: up %s %s listen %d key %s\n", dev.Name(), cfg.address,
		node.LocalAddr().Port(), base64.StdEncoding.EncodeToString(pub[:]))
	err = node.Run(ctx)
	s := node.Stats()
	fmt.Fprintf(os.Stderr, "malla: down: datagrams in %d out %d, tun in %d out %d, write errors %d\n",
		s.DatagramsIn, s.DatagramsOut, s.PacketsIn, s.PacketsOut, s.WriteErrors)
	return err
}

// meshBits is the prefix length of the mesh (D18, 10.200.0.0/16): the
// TUN's connected route covers every peer, whose allowed IP is its /32.
const meshBits = 16

// upMesh runs the node in mesh mode: it registers with the coordination
// (or starts from the cached map), gives the TUN the address the
// coordination assigned and follows the map until a signal arrives.
func upMesh(m *meshMode) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(m.listenPort)})
	if err != nil {
		return err
	}
	dev, err := tun.OpenLinux(m.tunName)
	if err != nil {
		conn.Close()
		return err
	}
	node, err := mesh.New(mesh.Config{
		PrivateKey: m.privateKey, Name: m.name, Tags: m.tags,
		CoordURL: m.coordURL, CoordFingerprint: m.coordFP, AuthKey: m.authKey,
		RelayURL: m.relayURL, RelayFingerprint: m.relayFP,
		StateDir: m.stateDir, Conn: conn, TUN: dev, MTU: mtu,
		OnEvent: logEvent,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	})
	if err != nil {
		conn.Close()
		dev.Close()
		return err
	}
	address := netip.PrefixFrom(node.Addr(), meshBits)
	if err := configureTUN(dev.Name(), &static{address: address}); err != nil {
		conn.Close()
		dev.Close()
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pub := node.PublicKey()
	fmt.Printf("malla: up %s %s listen %d key %s\n", dev.Name(), address,
		node.LocalAddr().Port(), base64.StdEncoding.EncodeToString(pub[:]))
	err = node.Run(ctx)
	s := node.Stats()
	fmt.Fprintf(os.Stderr, "malla: down: datagrams in %d out %d, relay in %d out %d, tun in %d out %d, write errors %d\n",
		s.DatagramsIn, s.DatagramsOut, s.RelayIn, s.RelayOut, s.PacketsIn, s.PacketsOut, s.WriteErrors)
	return err
}

// configureTUN gives the TUN its address and MTU, brings it up and routes
// every allowed-IPs prefix through it, with ip(8).
func configureTUN(name string, cfg *static) error {
	cmds := [][]string{
		{"addr", "add", cfg.address.String(), "dev", name},
		{"link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"},
	}
	for _, p := range cfg.dev.Peers {
		for _, pfx := range p.AllowedIPs {
			// The address prefix already has its connected route.
			if pfx.Bits() >= cfg.address.Bits() && cfg.address.Masked().Contains(pfx.Addr()) {
				continue
			}
			cmds = append(cmds, []string{"route", "replace", pfx.String(), "dev", name})
		}
	}
	for _, args := range cmds {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

func logEvent(e device.Event) {
	peer := "-"
	if e.Peer != ([32]byte{}) {
		peer = base64.StdEncoding.EncodeToString(e.Peer[:])[:8]
	}
	msg := fmt.Sprintf("malla: %s peer=%s", e.Kind, peer)
	if e.Reason != "" {
		msg += " reason=" + e.Reason
	}
	if e.Kind == device.EventEndpoint {
		msg += " endpoint=" + e.Endpoint.String()
	}
	fmt.Fprintln(os.Stderr, msg)
}
