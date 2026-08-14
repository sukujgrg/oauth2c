package yamlprint

import (
	"encoding/json"
	"math"
	"reflect"
	"time"
)

// jsonIntegers converts JSON-decoded whole numbers (float64 / json.Number)
// to int64 so YAML prints timestamps as 1786775334 instead of 1.786775334e+09.
func jsonIntegers(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case bool, string, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return x
	case float64:
		if n, ok := wholeInt64(x); ok {
			return n
		}
		return x
	case float32:
		return jsonIntegers(float64(x))
	case json.Number:
		return jsonNumber(x)
	case time.Time:
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = jsonIntegers(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = jsonIntegers(val)
		}
		return out
	default:
		return jsonIntegersValue(v)
	}
}

func jsonNumber(n json.Number) any {
	if i, err := n.Int64(); err == nil {
		return i
	}
	if f, err := n.Float64(); err == nil {
		return jsonIntegers(f)
	}
	return n.String()
}

func wholeInt64(f float64) (int64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	n := int64(f)
	if float64(n) != f {
		return 0, false
	}
	return n, true
}

func jsonIntegersValue(v any) any {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return v
	}

	switch rv.Kind() {
	case reflect.Pointer:
		if rv.IsNil() {
			return v
		}
		inner := jsonIntegers(rv.Elem().Interface())
		pv := reflect.New(rv.Type().Elem())
		iv := reflect.ValueOf(inner)
		if inner == nil {
			return pv.Interface()
		}
		if iv.IsValid() && iv.Type().AssignableTo(rv.Type().Elem()) {
			pv.Elem().Set(iv)
			return pv.Interface()
		}
		return v
	case reflect.Map:
		if rv.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		for iter := rv.MapRange(); iter.Next(); {
			val := jsonIntegers(iter.Value().Interface())
			mv := reflect.ValueOf(val)
			if val == nil || !mv.IsValid() || !mv.Type().AssignableTo(rv.Type().Elem()) {
				out.SetMapIndex(iter.Key(), iter.Value())
				continue
			}
			out.SetMapIndex(iter.Key(), mv)
		}
		return out.Interface()
	case reflect.Slice:
		if rv.IsNil() {
			return v
		}
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return v
		}
		out := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := 0; i < rv.Len(); i++ {
			val := jsonIntegers(rv.Index(i).Interface())
			mv := reflect.ValueOf(val)
			if val == nil || !mv.IsValid() || !mv.Type().AssignableTo(rv.Type().Elem()) {
				out.Index(i).Set(rv.Index(i))
				continue
			}
			out.Index(i).Set(mv)
		}
		return out.Interface()
	case reflect.Struct:
		out := reflect.New(rv.Type()).Elem()
		out.Set(rv)
		for i := 0; i < out.NumField(); i++ {
			fv := out.Field(i)
			if !fv.CanSet() || !fv.CanInterface() {
				continue
			}
			val := jsonIntegers(fv.Interface())
			mv := reflect.ValueOf(val)
			if val == nil || !mv.IsValid() || !mv.Type().AssignableTo(fv.Type()) {
				continue
			}
			fv.Set(mv)
		}
		return out.Interface()
	default:
		return v
	}
}
