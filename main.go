package main

import (
	"context"
	"fmt"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/semaphore"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
)

func ScanAndWriteResult(hostQuery string, ipAddresses []net.IP, parallelism int, reportFrequency int, outfile string) error {
	f, err := os.OpenFile(outfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("unable to create file: %v. Error: %v\n", outfile, err)
	}
	defer f.Close()

	var sem = semaphore.NewWeighted(int64(parallelism))
	var wg sync.WaitGroup

	query := PrepareQuestion(hostQuery)

	if _, err := f.WriteString(TelemetryHeader()); err != nil {
		log.Println("failed to write header to disk in output file.")
	}

	for scanID, ip := range ipAddresses {
		err := sem.Acquire(context.Background(), 1)
		if scanID%reportFrequency == 0 {
			fmt.Printf("Progress: [%v / %v]\n", scanID, len(ipAddresses))
		}
		if err != nil {
			log.Fatalf(fmt.Sprintf("failed to acquire semaphore. Index: %v\n", scanID))
		}
		wg.Add(1)
		go func(ip net.IP) {
			result := Probe(ip, query)
			if result != nil {
				if _, err := f.WriteString(result.Serialize()); err != nil {
					log.Println("failed to write to disk")
				}
			}
			sem.Release(1)
			wg.Done()
		}(ip)
	}

	wg.Wait()
	return nil
}

func VerifyDNS(ctx *cli.Context) error {
	inputFilePath := ctx.String("input")
	log.Printf("Reading file : %v\n", inputFilePath)
	ipAddresses := ReadInputFile(inputFilePath)
	log.Printf("Number of IPs : %v\n", len(ipAddresses))

	outputFile := ctx.String("output")
	parallelism := ctx.Int("parallelism")
	reportFrequency := ctx.Int("report")

	query := ctx.String("query")
	return ScanAndWriteResult(query, ipAddresses, parallelism, reportFrequency, outputFile)
}

func main() {
	app := &cli.App{
		Name:   "verify",
		Usage:  "Verify that the IP Address contains an open recursive DNS Resolver",
		Action: VerifyDNS,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "query",
				Aliases: []string{"q"},
				Usage:   "The query to make to each open resolver.",
				Value:   "google.com.",
			},
			&cli.StringFlag{
				Name:     "input",
				Aliases:  []string{"i"},
				Usage:    "The input file from the zmap output",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "output",
				Aliases:  []string{"o"},
				Usage:    "The output file to store the results of verifying the DNS resolvers",
				Required: true,
			},
			&cli.IntFlag{
				Name:    "parallelism",
				Aliases: []string{"p"},
				Value:   runtime.NumCPU(),
			},
			&cli.IntFlag{
				Name:    "report",
				Aliases: []string{"r"},
				Value:   10,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
