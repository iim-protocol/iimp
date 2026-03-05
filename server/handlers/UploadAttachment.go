package handlers

import (
	"io"
	"net/http"

	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/db"
	"github.com/iim-protocol/iimp/server/iimpserver"
	"github.com/iim-protocol/iimp/server/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func UploadAttachment(w http.ResponseWriter, r *http.Request) {
	// parse the request
	req, err := iimpserver.NewUploadAttachmentRequest(w, r)
	if err != nil {
		iimpserver.WriteUploadAttachment400Response(w, iimpserver.UploadAttachment400Response{})
		return
	}

	claims, err := auth.ValidateSessionToken(r.Context(), *req.Auth.Authorization)
	if err != nil {
		iimpserver.WriteUploadAttachment401Response(w, iimpserver.UploadAttachment401Response{})
		return
	}

	// size limit - 1000 MB
	r.Body = http.MaxBytesReader(w, r.Body, 1000*MB)

	metadata := bson.D{{Key: "uploadUserId", Value: claims.Subject}}

	uploadStream, err := db.Bucket.OpenUploadStream(r.Context(), req.Filename, options.GridFSUpload().SetMetadata(metadata))
	if err != nil {
		logger.Error.Printf("Failed to open upload stream for attachment: %v", err)
		iimpserver.WriteUploadAttachment500Response(w, iimpserver.UploadAttachment500Response{})
		return
	}
	defer uploadStream.Close()

	if _, err = io.Copy(uploadStream, r.Body); err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			logger.Error.Printf("Attachment size exceeds limit: %v", err)
			iimpserver.WriteUploadAttachment413Response(w, iimpserver.UploadAttachment413Response{})
			return
		}
		logger.Error.Printf("Failed to upload attachment bytes: %v", err)
		iimpserver.WriteUploadAttachment500Response(w, iimpserver.UploadAttachment500Response{})
		return
	}

	fileId, ok := uploadStream.FileID.(bson.ObjectID)
	if !ok {
		logger.Error.Printf("Failed to get file ID from upload stream: %v", err)
		iimpserver.WriteUploadAttachment500Response(w, iimpserver.UploadAttachment500Response{})
		return
	}
	iimpserver.WriteUploadAttachment201Response(w, iimpserver.UploadAttachment201Response{
		Body: iimpserver.UploadAttachment201ResponseBody{
			FileId: fileId.Hex(),
		},
	})
}
