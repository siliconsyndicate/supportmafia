package redisstorage

import (
	"fmt"
	"supportmafia/server/config"
	"time"

	"github.com/gomodule/redigo/redis"
)

// RedisStorage stores for redis client and redis config
type RedisStorage struct {
	Config *config.RedisConfig
	Conn   redis.Conn
	Client *redis.Pool
}

// Close closes redis connection
func (rs *RedisStorage) Close() {
	rs.Conn.Close()
}

// NewRedisStorage returns new redis instance
func NewRedisStorage(c *config.RedisConfig) *RedisStorage {
	client := &redis.Pool{
		// Maximum number of idle connections in the pool.
		MaxIdle: 15,
		// IdleTimeout: 240 * time.Second,
		// max number of connections
		Dial: func() (redis.Conn, error) {
			redisConnStart := time.Now()
			fmt.Println(c.ConnectionURL())
			c, err := redis.Dial("tcp", c.ConnectionURL())
			redisConnDuration := time.Since(redisConnStart)
			fmt.Println("redis connection latency = s%", redisConnDuration)
			if err != nil {
				return nil, err
			}
			return c, err

		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			if time.Since(t) < time.Minute {
				return nil
			}
			res, err := c.Do("PING")
			fmt.Println(res, err)
			return err
		},
	}
	return &RedisStorage{Client: client}
}

// Close closes redis connection
func (rs *RedisStorage) Do(commandName string, args ...interface{}) (reply interface{}, err error) {
	conn := rs.Client.Get()
	defer conn.Close()
	return conn.Do(commandName, args...)

}
