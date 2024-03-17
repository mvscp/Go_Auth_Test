package app

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
)

var mongoClient *mongo.Client
var userCollection *mongo.Collection

func ConnectDB() {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://127.0.0.1:27017"))
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to MongoDB!")

	userCollection = client.Database("test").Collection("users")
	mongoClient = client
	//userCollection.InsertOne(context.TODO(), bson.D{{"guid", "CF459FF-89A6-D451-513D-00CF4FC964FF"}})
	//userCollection.InsertOne(context.TODO(), bson.D{{"guid", "6F9619FF-8B86-D011-B42D-00CF4FC964FF"}})
}
