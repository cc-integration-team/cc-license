package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
)

func NewRunner() *Runner {
	return &Runner{}
}

type Runner struct {
	queue chan int
}

func (r *Runner) Run() {
	for data := range r.queue {
		slog.Info("Processing data", "data", data)
	}
}

func (r *Runner) Stop() {
	close(r.queue)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	runner := NewRunner()
	go runner.Run()
	for i := 0; i < 10; i++ {
		runner.queue <- i
	}
	runner.Stop()

	<-ctx.Done()
}
