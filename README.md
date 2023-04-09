# UDP-Broadcast

## Intalling

`go install`

## Running

List the ports to forward in `games.csv` and run the forwarder with

```
go run . [interface 1] [interface 2] [interface 3]...
```

For example

```
go run . eth0.10 eth0.11 eth0.12
```

