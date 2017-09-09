These tests are designed to provide functionality similar to unit tests.
However, they are designed to run directly against a working fileserver. 
As such, depending on the requirements of your file server, they require explicit parameters.
Edit the file:
test-server-config.json
to include a binding id, site id, server path, server port, and env.
Then run:
go test
If you run:
go test -v
it will also display certain log messages in addition to errors.
