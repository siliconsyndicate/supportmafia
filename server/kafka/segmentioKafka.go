package kafka

import (
	"context"
	"crypto/tls"
	"fmt"
	"supportmafia/server/config"
	"time"

	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
)

// NewSegmentioKafkaDialer returns new segmentio kafka dialer instance
func NewSegmentioKafkaDialer(c *config.KafkaConfig) *kafka.Dialer {
	dialer := &kafka.Dialer{
		Timeout: 10 * time.Second,
	}
	if c.Username != "" && c.Password != "" {
		fmt.Println("implementing plain mechanism")
		mechanism := plain.Mechanism{
			Username: c.Username,
			Password: c.Password,
		}
		dialer.TLS = &tls.Config{}
		dialer.SASLMechanism = mechanism
	}
	return dialer
}

// SegmentioConsumer implements `Consumer` methods
type SegmentioConsumer struct {
	Reader *kafka.Reader
	Logger *zerolog.Logger
}

// SegmentioConsumerOpts contains args required to create SegmentioConsumer instance
type SegmentioConsumerOpts struct {
	Logger *zerolog.Logger
	Config *config.ListenerConfig
}

// NewSegmentioKafkaConsumer returns an instance of kafka segmentio consumer
func NewSegmentioKafkaConsumer(opts *SegmentioConsumerOpts) *SegmentioConsumer {
	s := SegmentioConsumer{Logger: opts.Logger}
	s.Init(opts.Config)
	return &s
}

// Init initialize kafka consumer group
func (cl *SegmentioConsumer) Init(c *config.ListenerConfig) {
	dialer := &kafka.Dialer{
		Timeout: 10 * time.Second,
	}
	if c.Username != "" && c.Password != "" {
		fmt.Println("implementing plain mechanism")
		mechanism := plain.Mechanism{
			Username: c.Username,
			Password: c.Password,
		}
		dialer.TLS = &tls.Config{}
		dialer.SASLMechanism = mechanism
	}
	cl.Reader = kafka.NewReader(kafka.ReaderConfig{
		Brokers:  c.Brokers,
		GroupID:  c.GroupID,
		Topic:    c.Topic,
		Dialer:   dialer,
		MaxBytes: 10e6, // 10MB
	})
}

// Consume consumes messages from kafka topic but does not commit them
func (cl *SegmentioConsumer) Consume(ctx context.Context, f func(Message)) {
	for {
		m, err := cl.Reader.FetchMessage(ctx)
		if err != nil {
			cl.Logger.Err(err).Msg("failed to fetch messages")
			break
		}
		f(m)
	}
}

// Commit commits an existing message
func (cl *SegmentioConsumer) Commit(ctx context.Context, m Message) {
	if err := cl.Reader.CommitMessages(ctx, m.(kafka.Message)); err != nil {
		cl.Logger.Err(err).Msg("failed to commit messages")
	}
}

// ConsumeAndCommit consumes a message and commits instantly
func (cl *SegmentioConsumer) ConsumeAndCommit(ctx context.Context, f func(Message)) {
	for {
		m, err := cl.Reader.ReadMessage(ctx)
		if err != nil {
			cl.Logger.Err(err).Msg("failed to fetch messages")
			break
		}
		f(m)
	}
}

// Close closes the consumer connection
func (cl *SegmentioConsumer) Close() {
	if err := cl.Reader.Close(); err != nil {
		cl.Logger.Err(err).Msg("failed to close reader")
	}
}

// SegmentioProducerImpl implements `Producer` methods
type SegmentioProducer struct {
	Writer *kafka.Writer
	Logger *zerolog.Logger
}

// SegmentioProducerOpts contains args required to create a new instance of SegmentioProducerImpl
type SegmentioProducerOpts struct {
	Logger *zerolog.Logger
	Config *config.ProducerConfig
}

func NewSegmentioProducer(opts *SegmentioProducerOpts) *SegmentioProducer {
	p := SegmentioProducer{
		Logger: opts.Logger,
	}
	p.Init(opts.Config)
	return &p
}

func (pl *SegmentioProducer) Init(c *config.ProducerConfig) {
	dialer := &kafka.Dialer{
		Timeout: 10 * time.Second,
	}
	if c.Username != "" && c.Password != "" {
		fmt.Println("implementing plain mechanism")
		mechanism := plain.Mechanism{
			Username: c.Username,
			Password: c.Password,
		}
		dialer.TLS = &tls.Config{}
		dialer.SASLMechanism = mechanism
	}

	pl.Writer = kafka.NewWriter(kafka.WriterConfig{
		Brokers: c.Brokers,
		Topic:   c.Topic,
		Async:   c.Async,
		Dialer:  dialer,
	})
}

func (pl *SegmentioProducer) Publish(m Message) {
	ctx := context.TODO()
	if err := pl.Writer.WriteMessages(ctx, m.(kafka.Message)); err != nil {
		pl.Logger.Err(err).Interface("m", m).Msg("Failed to publish kafka message")
	}
}

func (pl *SegmentioProducer) Close() {
	if err := pl.Writer.Close(); err != nil {
		pl.Logger.Err(err).Msg("Failed to close producer")
	}
}
