package util

import "go.mongodb.org/mongo-driver/bson/primitive"

//ReferenceField used to loosley reference document
type ReferenceField struct {
	Col      string             `json:"_col" bson:"_col"`
	ObjectID primitive.ObjectID `json:"_id" bson:"_id"`
}
