package util

import (
	"time"
)

func GetFirstOfTheMonth(now time.Time) time.Time {
	currentYear, currentMonth, _ := now.Date()
	currentLocation := now.Location()

	firstOfMonth := time.Date(currentYear, currentMonth, 1, 0, 0, 0, 0, currentLocation)
	return firstOfMonth
}
