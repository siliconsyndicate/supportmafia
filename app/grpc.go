package app

import (

	//	entity_proto "proto/entity"

	"github.com/opensearch-project/opensearch-go"
	"go.mongodb.org/mongo-driver/mongo"
)

// Note: Replace "entity_proto" and the respective functions with server specific functions

// GRPC server initializer. All GRPC functions will be an implementation of this struct
type Grpc struct {
	App *App
	DB  *mongo.Database
	ES  *opensearch.Client
	//entity_proto.UnimplementedEntityServer
}

// Example GRPC server function
// Input: context and request structure from the service proto file
// Output: response structure from the service proto file and error
// func (s *Grpc) HelloEntity(ctx context.Context, in *entity_proto.EntityRequest) (*entity_proto.EntityResponse, error) {
// 	var result model.User
// 	err := s.DB.Collection(model.SampleColl).FindOne(ctx, bson.M{"username": "sample"}).Decode(&result)
// 	if err != nil {
// 		fmt.Println(err)
// 	}

// 	fmt.Printf("%+v", result)
// 	fmt.Println("received from core")

// 	return &entity_proto.EntityResponse{
// 		Message:     "core requested to entity\n",
// 		Value:       200 + in.GetValue(),
// 		RespondedAt: in.GetRequestedAt(),
// 	}, nil
// }
