package cache

import (
	"testing"
	"time"
)

func TestGenericCache(t *testing.T) {
	c := NewGeneric[string, string](5 * time.Minute)

	c.Set("foo", "bar", 0)
	if v, found := c.Get("foo"); !found || v != "bar" {
		t.Errorf("expected foo=bar, got %v (found=%v)", v, found)
	}

	c.Delete("foo")
	if _, found := c.Get("foo"); found {
		t.Error("expected foo to be deleted")
	}
}

func TestGenericCacheExpiration(t *testing.T) {
	defaultDuration := 50 * time.Millisecond
	c := NewGeneric[string, int](defaultDuration)

	c.Set("a", 1, defaultDuration)
	c.Set("b", 2, -1) // No expiration

	time.Sleep(2 * defaultDuration)

	if _, found := c.Get("a"); found {
		t.Error("expected 'a' to expire")
	}

	if v, found := c.Get("b"); !found || v != 2 {
		t.Errorf("expected 'b' to persist, got %v (found=%v)", v, found)
	}
}

func TestGenericCacheTypes(t *testing.T) {
	cInt := NewGeneric[int, int](time.Minute)
	cInt.Set(1, 100, 0)
	if v, found := cInt.Get(1); !found || v != 100 {
		t.Errorf("expected 1=100, got %v", v)
	}

	type User struct {
		Name string
		Age  int
	}
	cUser := NewGeneric[string, User](time.Minute)
	u := User{Name: "Alice", Age: 30}
	cUser.Set("u1", u, 0)

	if got, found := cUser.Get("u1"); !found || got != u {
		t.Errorf("expected user %v, got %v", u, got)
	}
}
