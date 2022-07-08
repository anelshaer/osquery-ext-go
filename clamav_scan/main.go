package main

import (
	"context"
	"errors"
	"flag"
	"github/osquery-go"
	"io"
	"log"
	"os"
	"time"

	"github.com/dutchcoders/go-clamd"
	"github.com/osquery/osquery-go/plugin/table"
)

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
)

func main() {
	flag.Parse()
	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}
	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		"clamav_scan",
		*socket,
		serverTimeout,
		serverPingInterval,
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a Generate function.
	server.RegisterPlugin(table.NewPlugin("clamav_scan", clamavColumns(), clamavGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

// clamavColumns returns the columns that our table will return.
func clamavColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("path"),
		table.TextColumn("result"),
		table.TextColumn("status"),
		table.TextColumn("raw"),
		table.TextColumn("socket"),
	}
}

// clamavGenerate will be called whenever the table is queried. It should return
// a full table scan.
func clamavGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	var clamSocket string
	var path string

	cnstListSocket, ok := queryContext.Constraints["socket"]
	if ok && len(cnstListSocket.Constraints) == 0 {
		return results, errors.New("The clamav_scan table requires a clamav socket using WHERE socket =")
	}

	if ok { // If we have a constraint on path limit it to the = operator
		for _, constraint := range cnstListSocket.Constraints {
			if constraint.Operator != table.OperatorEquals {
				return results, errors.New("The clamav_scan table only accepts = constraints on the socket column")
			}
			clamSocket = constraint.Expression
		}
	}

	cnstList, ok := queryContext.Constraints["path"]
	if ok && len(cnstList.Constraints) == 0 {
		return results, errors.New("The clamav_scan table requires that you specify a constraint WHERE path =")
	}

	if ok { // If we have a constraint on path limit it to the = operator
		for _, constraint := range cnstList.Constraints {
			if constraint.Operator != table.OperatorEquals {
				return results, errors.New("The clamav_scan table only accepts = constraints on the path column")
			}
			path = constraint.Expression
		}
	}

	c := clamd.NewClamd(clamSocket)
	if err := c.Ping(); err != nil {
		return results, errors.New("The clamav_scan table requires a valid clamav socket")
	}
	file, err := os.Open(path)
	if err != nil {
		return []map[string]string{
			{
				"path":   path,
				"result": "File Not Found",
				"status": "",
				"raw":    "",
				"socket": clamSocket,
			},
		}, nil
	}
	defer file.Close()

	var reader io.Reader = file
	response, err := c.ScanStream(reader, make(chan bool))

	if err != nil {
		return []map[string]string{
			{
				"path":   path,
				"result": "File can't be scanned",
				"status": "",
				"raw":    "",
				"socket": clamSocket,
			},
		}, nil
	}

	for s := range response {
		results = append(results, map[string]string{
			"path":   path,
			"result": s.Description,
			"status": s.Status,
			"raw":    s.Raw,
			"socket": clamSocket,
		})
	}
	return results, nil
}
