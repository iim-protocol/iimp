package handlers

import (
	"net/http"
	"time"

	dbmodels "github.com/iim-protocol/iimp/sdk/db-models"
	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func PullUserEvents(w http.ResponseWriter, r *http.Request) {
	// parse the request
	req, err := iimpserver.NewPullUserEventsRequest(w, r)
	if err != nil {
		logger.Error.Printf("Failed to parse PullUserEvents request: %v", err)
		iimpserver.WritePullUserEvents400Response(w, iimpserver.PullUserEvents400Response{})
		return
	}

	claims, err := auth.ValidateSessionToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		logger.Error.Printf("Failed to validate session token: %v", err)
		iimpserver.WritePullUserEvents401Response(w, iimpserver.PullUserEvents401Response{})
		return
	}

	userId := claims.Subject

	eventsFilter := bson.D{{Key: "user_id", Value: userId}}

	if req.Cursor != nil {
		cursorId, err := bson.ObjectIDFromHex(*req.Cursor)
		if err != nil {
			logger.Error.Printf("Failed to parse cursor ID: %v", err)
			iimpserver.WritePullUserEvents400Response(w, iimpserver.PullUserEvents400Response{})
			return
		}
		eventsFilter = append(eventsFilter, bson.E{Key: "_id", Value: bson.D{{Key: "$gt", Value: cursorId}}})
	}

	if req.Limit == nil || *req.Limit <= 0 {
		defLimit := 50.0
		req.Limit = &defLimit
	} else if *req.Limit > 100 {
		maxLimit := 100.0
		req.Limit = &maxLimit
	}

	events := make([]dbmodels.UserEvent, 0, int(*req.Limit)+1)
	cursor, err := db.DB.Collection(dbmodels.UserEventsCollection).Find(r.Context(), eventsFilter, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}).SetLimit(int64(*req.Limit)+1))
	if err != nil {
		logger.Error.Printf("Failed to fetch user events from database: %v", err)
		iimpserver.WritePullUserEvents500Response(w, iimpserver.PullUserEvents500Response{})
		return
	}

	if err = cursor.All(r.Context(), &events); err != nil {
		logger.Error.Printf("Failed to decode user events from database cursor: %v", err)
		iimpserver.WritePullUserEvents500Response(w, iimpserver.PullUserEvents500Response{})
		return
	}

	var nextCursor *string
	moreAvailable := len(events) > int(*req.Limit)
	if moreAvailable {
		nc := events[len(events)-2].Id.Hex()
		nextCursor = &nc
	}

	responseEventsCount := len(events)
	if moreAvailable {
		responseEventsCount = len(events) - 1
	}

	responseEvents := make([]iimpserver.PullUserEvents200ResponseBodyEventsItem, responseEventsCount)
	for i := 0; i < responseEventsCount; i++ {
		event := events[i]
		payload := (map[string]any)(event.Payload)
		responseEvents[i] = iimpserver.PullUserEvents200ResponseBodyEventsItem{
			EventId:   event.Id.Hex(),
			EventType: event.EventType,
			Payload:   &payload,
			CreatedAt: event.Id.Timestamp().Format(time.RFC3339),
		}
	}

	iimpserver.WritePullUserEvents200Response(w, iimpserver.PullUserEvents200Response{
		Body: iimpserver.PullUserEvents200ResponseBody{
			Events:     responseEvents,
			NextCursor: nextCursor,
		},
	})
}
