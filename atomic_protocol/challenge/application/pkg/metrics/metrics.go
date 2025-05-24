

package metrics

import (
	"sync"
	"time"
)


type sizeObservation struct {
    value float64
    timestamp time.Time
}


type MetricsCollector struct {
	counters map[string]map[string]int64
	latencies map[string][]time.Duration
	sizes map[string][]sizeObservation
	mutex sync.RWMutex
}


func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		counters: make(map[string]map[string]int64),
		latencies: make(map[string][]time.Duration),
		sizes: make(map[string][]sizeObservation),
		mutex: sync.RWMutex{},
	}
}


func (mc *MetricsCollector) IncrementCounter(name string, labels map[string]string) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	
	labelKey := "default"
	if labels != nil && len(labels) > 0 {
		
		for k, v := range labels {
			labelKey = k + ":" + v
			break 
		}
	}
	
	
	if _, exists := mc.counters[name]; !exists {
		mc.counters[name] = make(map[string]int64)
	}
	
	
	mc.counters[name][labelKey]++
}


func (mc *MetricsCollector) ObserveLatency(name string, duration time.Duration) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	
	
	if _, exists := mc.latencies[name]; !exists {
		mc.latencies[name] = make([]time.Duration, 0)
	}
	
	
	mc.latencies[name] = append(mc.latencies[name], duration)
	
	
	if len(mc.latencies[name]) > 100 {
		mc.latencies[name] = mc.latencies[name][len(mc.latencies[name])-100:]
	}
}


func (mc *MetricsCollector) ObserveSize(name string, size float64) {
    mc.mutex.Lock()
    defer mc.mutex.Unlock()
    
    
    if _, exists := mc.sizes[name]; !exists {
        mc.sizes[name] = make([]sizeObservation, 0)
    }
    
    
    mc.sizes[name] = append(mc.sizes[name], sizeObservation{
        value: size,
        timestamp: time.Now(),
    })
    
    
    if len(mc.sizes[name]) > 100 {
        mc.sizes[name] = mc.sizes[name][len(mc.sizes[name])-100:]
    }
}


func (mc *MetricsCollector) GetCounters() map[string]map[string]int64 {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	
	
	counters := make(map[string]map[string]int64)
	for name, labels := range mc.counters {
		counters[name] = make(map[string]int64)
		for label, value := range labels {
			counters[name][label] = value
		}
	}
	
	return counters
}


func (mc *MetricsCollector) GetLatencies() map[string]map[string]float64 {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	
	
	result := make(map[string]map[string]float64)
	
	for name, durations := range mc.latencies {
		if len(durations) == 0 {
			continue
		}
		
		result[name] = make(map[string]float64)
		
		
		var sum time.Duration
		for _, d := range durations {
			sum += d
		}
		result[name]["avg_ms"] = float64(sum) / float64(len(durations)) / float64(time.Millisecond)
		
		
	}
	
	return result
}


func (mc *MetricsCollector) GetSizes() map[string]map[string]float64 {
    mc.mutex.RLock()
    defer mc.mutex.RUnlock()
    
    result := make(map[string]map[string]float64)
    
    for name, observations := range mc.sizes {
        if len(observations) == 0 {
            continue
        }
        
        result[name] = make(map[string]float64)
        
        
        var sum float64
        for _, obs := range observations {
            sum += obs.value
        }
        result[name]["avg_bytes"] = sum / float64(len(observations))
        
        
        var max float64
        for _, obs := range observations {
            if obs.value > max {
                max = obs.value
            }
        }
        result[name]["max_bytes"] = max
    }
    
    return result
}
