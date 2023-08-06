package app

import (
	"context"
	"strings"
	"supportmafia/model"
	"supportmafia/schema"
	"time"

	"github.com/opensearch-project/opensearch-go"
	"github.com/rs/zerolog"
	errors "github.com/vasupal1996/goerror"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Ticket defines methods of Ticket service to be implemented
type Ticket interface {
	CreateTicket(*schema.ValidateCreateTicket) (*model.Ticket, error)
	GetTicketAll(string, string) ([]model.Ticket, error)
	GetTicketByID(primitive.ObjectID) (*model.Ticket, error)
	PrioritizeTicket(*schema.ValidatePrioritizeTicket) (*model.Ticket, error)
	ResolveTicket(*schema.ValidateResolveTicket) (*model.Ticket, error)
	AssignTicket(*schema.ValidateAssignTicket) (*model.Ticket, error)
	CloseTicket(*schema.ValidateCloseTicket) (*model.Ticket, error)
	ConversationReply(*schema.ValidateConversationReply) (*model.Conversation, error)
	UserFeedback(*schema.ValidateUserFeedback) (*model.Ticket, error)
	ReplyToAllTickets(*schema.ValidateReplyToAllTickets) (bool, error)
}

// TicketOpts contains arguments to be accepted for new instance of Ticket service
type TicketOpts struct {
	App    *App
	DB     *mongo.Database
	ES     *opensearch.Client
	Logger *zerolog.Logger
}

// TicketImpl implements Ticket service
type TicketImpl struct {
	App    *App
	DB     *mongo.Database
	ES     *opensearch.Client
	Logger *zerolog.Logger
}

// InitTicket returns initializes Ticket service
func InitTicket(opts *TicketOpts) Ticket {
	e := &TicketImpl{
		App:    opts.App,
		DB:     opts.DB,
		ES:     opts.ES,
		Logger: opts.Logger,
	}
	return e
}

func (t *TicketImpl) CreateTicket(v *schema.ValidateCreateTicket) (*model.Ticket, error) {
	now := time.Now().UTC()
	var traces []model.Trace

	if len(v.Traces) > 0 {
		for _, trace := range v.Traces {
			new_trace := model.Trace{
				Key:   trace.Key,
				Value: trace.Value,
			}
			traces = append(traces, new_trace)
		}
	}

	ticket := &model.Ticket{
		Topic:       v.Topic,
		Description: v.Description,
		Attachments: v.Attachments,
		Category:    v.Category,
		Status:      "open",
		Priority:    "new",
		Traces:      traces,
		CreatedAt:   &now,
		IsOpen:      true,
		Platform:    v.Platform,
		CreatedBy: &model.UserModel{
			UserID: v.CreatedBy.UserID,
			Name:   v.CreatedBy.Name,
		},
	}

	// creating session for atomic updates
	session, err := t.DB.Client().StartSession()
	if err != nil {
		return nil, errors.Wrap(err, "Unable to create db session", &errors.DBError)
	}
	// Closing session at the end for function execution
	defer session.EndSession(context.TODO())

	// staring a new transaction
	if err := session.StartTransaction(); err != nil {
		return nil, errors.Wrap(err, "Unable to start transaction", &errors.DBError)
	}
	if err := mongo.WithSession(context.TODO(), session, func(sc mongo.SessionContext) error {

		// inserting ticket into mongodb
		res, err := t.DB.Collection(model.TicketColl).InsertOne(context.TODO(), ticket)
		if err != nil {
			session.AbortTransaction(sc)
			return errors.Wrap(err, "Failed to insert ticket into mongodb", &errors.DBError)
		}
		ticketID := res.InsertedID.(primitive.ObjectID)
		ticket.ID = &ticketID

		// inserting conversation into mongodb
		conversation := &model.Conversation{
			TicketID:    ticket.ID,
			Message:     ticket.Description,
			Attachments: ticket.Attachments,
			CreatedAt:   &now,
			CreatedBy: &model.UserModel{
				UserID: v.CreatedBy.UserID,
				Name:   v.CreatedBy.Name,
			},
		}
		ress, err := t.DB.Collection(model.ConversationColl).InsertOne(context.TODO(), conversation)
		if err != nil {
			session.AbortTransaction(sc)
			return errors.Wrap(err, "Failed to insert conversation into mongodb", &errors.DBError)
		}
		conversationID := ress.InsertedID.(primitive.ObjectID)
		conversation.ID = &conversationID

		// Committing transaction
		if err := session.CommitTransaction(sc); err != nil {
			return errors.Wrap(err, "Failed to commit", &errors.DBError)
		}
		return nil
	}); err != nil {
		t.Logger.Err(err).Msg("CreateTicket.mongo.WithSession")
		return nil, err
	}

	return ticket, nil
}

// GetTicketAll returns ticket based on status and userID filter
func (t *TicketImpl) GetTicketAll(status, user string) ([]model.Ticket, error) {
	var tickets []model.Ticket

	opts := options.Find().SetSort(bson.M{"_id": -1})
	filter := bson.M{}
	//status filter
	statusArray := strings.Split(status, ",")
	if len(statusArray) > 1 {
		filter["status"] = bson.M{"$in": statusArray}
	} else if len(statusArray) == 1 && statusArray[0] != "" {
		filter["status"] = statusArray[0]
	}

	//user filter
	userArray := strings.Split(user, ",")
	if len(userArray) > 1 {
		filter["created_by.name"] = bson.M{"$in": userArray}
	} else if len(userArray) == 1 && userArray[0] != "" {
		filter["created_by.name"] = userArray[0]
	}

	//fetching tickets
	cur, err := t.DB.Collection(model.TicketColl).Find(context.TODO(), filter, opts)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to query database", &errors.DBError)
	}
	if err := cur.All(context.TODO(), &tickets); err != nil {
		return nil, errors.Wrap(err, "Failed to fetch tickets", &errors.DBError)
	}

	return tickets, nil
}

// GetTicketByID returns ticket based on ticketID
func (t *TicketImpl) GetTicketByID(ticketID primitive.ObjectID) (*model.Ticket, error) {
	var ticket *model.Ticket

	filter := bson.M{"_id": ticketID}
	if err := t.DB.Collection(model.TicketColl).FindOne(context.TODO(), filter).Decode(&ticket); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.Wrap(err, "Ticket not found", &errors.DBError)
		}
		return nil, errors.Wrap(err, "Failed to query database", &errors.DBError)
	}

	return ticket, nil
}

// PrioritizeTicket changes priority of ticket based on ticketID
func (t *TicketImpl) PrioritizeTicket(v *schema.ValidatePrioritizeTicket) (*model.Ticket, error) {
	var ticket *model.Ticket

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	filter := bson.M{"_id": v.TicketID}
	update := bson.M{
		"$set": bson.M{
			"priority": v.Priority,
		},
	}
	if err := t.DB.Collection(model.TicketColl).FindOneAndUpdate(context.TODO(), filter, update, opts).Decode(&ticket); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.Wrap(err, "Ticket not found", &errors.DBError)
		}
		return nil, errors.Wrap(err, "Failed to query database", &errors.DBError)
	}

	return ticket, nil
}

// ResolveTicket sets status to resolved based on ticketID
func (t *TicketImpl) ResolveTicket(v *schema.ValidateResolveTicket) (*model.Ticket, error) {
	var ticket *model.Ticket

	resolvedBy := &model.UserModel{
		UserID: v.ResolvedBy.UserID,
		Name:   v.ResolvedBy.Name,
		Email:  v.ResolvedBy.Email,
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	filter := bson.M{"_id": v.TicketID}
	update := bson.M{
		"$set": bson.M{
			"status":      "resolved",
			"is_resolved": true,
			"resolved_by": resolvedBy,
			"resolved_at": time.Now().UTC(),
		},
	}
	if err := t.DB.Collection(model.TicketColl).FindOneAndUpdate(context.TODO(), filter, update, opts).Decode(&ticket); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.Wrap(err, "Ticket not found", &errors.DBError)
		}
		return nil, errors.Wrap(err, "Failed to query database", &errors.DBError)
	}

	return ticket, nil
}

// AssignTicket assigns ticket to agent based on ticketID
func (t *TicketImpl) AssignTicket(v *schema.ValidateAssignTicket) (*model.Ticket, error) {
	var ticket *model.Ticket

	assignedTo := &model.UserModel{
		UserID: v.AssignedTo.UserID,
		Name:   v.AssignedTo.Name,
		Email:  v.AssignedTo.Email,
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	filter := bson.M{"_id": v.TicketID}
	update := bson.M{
		"$set": bson.M{
			"assigned_to": assignedTo,
			"assigned_at": time.Now().UTC(),
		},
	}
	if err := t.DB.Collection(model.TicketColl).FindOneAndUpdate(context.TODO(), filter, update, opts).Decode(&ticket); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.Wrap(err, "Ticket not found", &errors.DBError)
		}
		return nil, errors.Wrap(err, "Failed to query database", &errors.DBError)
	}

	return ticket, nil
}

// CloseTicket closes ticket based on ticketID
func (t *TicketImpl) CloseTicket(v *schema.ValidateCloseTicket) (*model.Ticket, error) {
	now := time.Now().UTC()
	var ticket *model.Ticket

	closedBy := &model.UserModel{
		Type:   v.UserTye,
		UserID: v.ClosedBy.UserID,
		Name:   v.ClosedBy.Name,
	}
	if v.ClosedBy.Email != "" {
		closedBy.Email = v.ClosedBy.Email
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	filter := bson.M{"_id": v.TicketID}
	update := bson.M{
		"$set": bson.M{
			"status":    "closed",
			"is_closed": true,
			"closed_at": &now,
			"closed_by": closedBy,
		},
	}
	if err := t.DB.Collection(model.TicketColl).FindOneAndUpdate(context.TODO(), filter, update, opts).Decode(&ticket); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.Wrap(err, "Ticket not found", &errors.DBError)
		}
		return nil, errors.Wrap(err, "Failed to query database", &errors.DBError)
	}

	return ticket, nil
}

// Conversation reply to ticket by user or agent
func (t *TicketImpl) ConversationReply(v *schema.ValidateConversationReply) (*model.Conversation, error) {
	now := time.Now().UTC()

	createdBy := &model.UserModel{
		Type:   v.UserTye,
		UserID: v.CreatedBy.UserID,
		Name:   v.CreatedBy.Name,
	}
	if v.CreatedBy.Email != "" {
		createdBy.Email = v.CreatedBy.Email
	}

	// inserting conversation into mongodb
	conversation := &model.Conversation{
		TicketID:    v.TicketID,
		Message:     v.Message,
		Attachments: v.Attachments,
		CreatedAt:   &now,
		CreatedBy:   createdBy,
	}
	res, err := t.DB.Collection(model.ConversationColl).InsertOne(context.TODO(), conversation)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to insert conversation into mongodb", &errors.DBError)
	}
	conversationID := res.InsertedID.(primitive.ObjectID)
	conversation.ID = &conversationID

	return conversation, nil
}

// UserFeedback save user feedback to ticket based on ticketID
func (t *TicketImpl) UserFeedback(v *schema.ValidateUserFeedback) (*model.Ticket, error) {
	var ticket *model.Ticket

	feedback := &model.Feedback{
		Rating:      v.Feedback.Rating,
		Description: v.Feedback.Description,
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	filter := bson.M{"_id": v.TicketID}
	update := bson.M{
		"$set": bson.M{
			"feedback": feedback,
		},
	}
	if err := t.DB.Collection(model.TicketColl).FindOneAndUpdate(context.TODO(), filter, update, opts).Decode(&ticket); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.Wrap(err, "Ticket not found", &errors.DBError)
		}
		return nil, errors.Wrap(err, "Failed to query database", &errors.DBError)
	}

	return ticket, nil
}

// ReplyToAllTicket reply to all ticket by agent
func (t *TicketImpl) ReplyToAllTickets(v *schema.ValidateReplyToAllTickets) (bool, error) {
	now := time.Now().UTC()
	var conversations []interface{}
	createdBy := &model.UserModel{
		Type:   v.UserTye,
		UserID: v.CreatedBy.UserID,
		Name:   v.CreatedBy.Name,
		Email:  v.CreatedBy.Email,
	}
	for _, ticket := range v.TicketIDs {
		// inserting conversation into mongodb
		conversation := model.Conversation{
			TicketID:  &ticket,
			Message:   v.Message,
			CreatedAt: &now,
			CreatedBy: createdBy,
		}
		if len(v.Attachments) > 0 {
			conversation.Attachments = v.Attachments
		}
		conversations = append(conversations, conversation)
	}

	_, err := t.DB.Collection(model.ConversationColl).InsertMany(context.TODO(), conversations)
	if err != nil {
		return false, errors.Wrap(err, "Failed to insert conversations into database", &errors.DBError)
	}

	return true, nil
}
