//go:generate $GOPATH/bin/mockgen -destination=../../mock/mock_producer.go -package=mock supportmafia/server/kafka Producer

package kafka

import (
	"context"
	"supportmafia/server/config"
)

// Kafka used by server to implement Kafka.
type Kafka interface {
	Close()
}

// Message defines kafka message implementation
type Message interface{}

// Consumer defines how a kafka consumer should be implemented
type Consumer interface {
	Init(*config.ListenerConfig)
	Consume(context.Context, func(Message))
	Commit(context.Context, Message)
	ConsumeAndCommit(context.Context, func(Message))
	Close()
}

// Producer defines how kafka producer should be implemented
type Producer interface {
	Init(*config.ProducerConfig)
	Publish(Message)
	Close()
}
