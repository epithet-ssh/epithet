package broker

import "sync"

type Broker struct {
	lock      sync.Mutex
	done      chan struct{}
	closeOnce sync.Once
}

func (b *Broker) Done() <-chan struct{} {
	return b.done
}

func (b *Broker) Close() {
	b.closeOnce.Do(func() {
		close(b.done)
	})
}

func (b *Broker) Running() bool {
	select {
	case <-b.Done():
		return false
	default:
		return true
	}
}
