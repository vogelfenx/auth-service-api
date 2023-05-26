while ! nc -z $POSTGRES_HOST $POSTGRES_PORT; do
      sleep 0.1
done
echo "Postgres database is working successfully"

while ! nc -z $REDIS_HOST $REDIS_PORT; do
      sleep 0.1
done
echo "Redis database is working successfully"