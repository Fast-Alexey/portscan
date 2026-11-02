# portscan

Пакет для параллельного Connect-сканирования TCP-портов на Go с поддержкой контекста и классификацией ошибок.

## Особенности

- Использование только стандартной библиотеки Go.
- Классификация сетевых состояний (`open`, `closed`, `timeout`, `unreachable`, `canceled`, `error`) без строкового сравнения ошибок.
- Настраиваемый пул воркеров (`WithConcurrency`) и таймаут (`WithConnectTimeout`).
- Безопасность при медленном вычитывании результатов клиентом (Slow Consumer).
- Потокобезопасный `Scanner`, готовый к повторному использованию.

## Использование

```go
package main

import (
	"context"
	"fmt"
	"time"

	"[github.com/Fast-Alexey/portscan](https://github.com/Fast-Alexey/portscan)"
)

func main() {
	scanner, err := portscan.New(
		portscan.WithConcurrency(50),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1", "google.com"},
		portscan.Combine(
			portscan.Ports(80, 443),
			portscan.Range(8000, 8080),
		),
	)
	if err != nil {
		panic(err)
	}

	for res := range results {
		fmt.Println(res)
	}
}
