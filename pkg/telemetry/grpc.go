package telemetry

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
)

// EngineClient returns dial options recording every call to the simulation
// engine (F-012 T-09; AC-22): the method (Info, Simulate, Aggregate), the
// outcome and the duration, streams until they end.
func EngineClient() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			start := time.Now()
			err := invoker(ctx, method, req, reply, cc, opts...)
			EngineCall(ctx, methodName(method), err, time.Since(start))
			return err
		}),
		grpc.WithChainStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			start := time.Now()
			s, err := streamer(ctx, desc, cc, method, opts...)
			if err != nil {
				EngineCall(ctx, methodName(method), err, time.Since(start))
				return nil, err
			}
			return &timedStream{ClientStream: s, ctx: ctx, method: methodName(method), start: start}, nil
		}),
	}
}

// methodName is the RPC's name, the last element of /package.Service/Method.
func methodName(full string) string {
	if i := strings.LastIndexByte(full, '/'); i >= 0 {
		return full[i+1:]
	}
	return full
}

type timedStream struct {
	grpc.ClientStream
	ctx    context.Context
	method string
	start  time.Time
	once   sync.Once
}

func (s *timedStream) RecvMsg(m any) error {
	err := s.ClientStream.RecvMsg(m)
	if err != nil {
		s.once.Do(func() {
			end := err
			if errors.Is(err, io.EOF) {
				end = nil
			}
			EngineCall(s.ctx, s.method, end, time.Since(s.start))
		})
	}
	return err
}
