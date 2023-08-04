package model

// HeaderRequestID sets RequestID in request header
const HeaderRequestID string = "X-Request-ID"

// Authentication sets Authentication in request header
const Authentication string = "Authentication"

// Mongodb collections
const (
	SampleColl       = "sample"
	SprintColl       = "sprint"
	UserColl         = "users"
	OrganizationColl = "organization"
	TeamsColl        = "teams"
	MilestonesColl   = "milestones"
	TasksColl        = "tasks"
	UserStoriesColl  = "user_stories"
)
