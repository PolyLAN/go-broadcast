edit the list of game to your liking then run:

```
docker build -t proxy . && docker run --net=host proxy $INTERFACES
```
