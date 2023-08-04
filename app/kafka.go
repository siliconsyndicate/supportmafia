package app

func InitConsumer(a *App) {

	// ctx := context.TODO()

	// a.ActivityTrackingConsumer = kafka.NewSegmentioKafkaConsumer(&kafka.SegmentioConsumerOpts{
	// 	Logger: a.Logger,
	// 	Config: &a.Config.ActivityTrackingConsumerConfig,
	// })
	// go a.ActivityTrackingConsumer.ConsumeAndCommit(ctx, a.Warehouse.ActivityConsumer)

	// go a.Warehouse.CronJob()

}

func InitProducer(a *App) {

	// a.ActivityTrackingProducer = kafka.NewSegmentioProducer(&kafka.SegmentioProducerOpts{
	// 	Logger: a.Logger,
	// 	Config: &a.Config.ActivityTrackingProducerConfig,
	// })

}
