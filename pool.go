package jwt

import "sync"

type devicePool[T any] struct {
	cleanup func(T)
	p       sync.Pool
}

func newPool[T any](create func() T, cleanup func(T)) devicePool[T] {
	return devicePool[T]{
		cleanup: cleanup,
		p: sync.Pool{
			New: func() any {
				return create()
			},
		},
	}
}

func (t devicePool[T]) Get() T {
	return t.p.Get().(T)
}

func (t devicePool[T]) Put(v T) {
	t.cleanup(v)
	t.p.Put(v)
}
