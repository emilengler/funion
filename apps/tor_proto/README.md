# TorProto

Implements the Tor protocol using GenServer.

## Architecture

The general architecture of a Tor protocol process tree looks as
follows:

* Connection 1
    * Satellite
	* Circuit 1
	    * Stream 1
		* ...
		* Stream N
	* ...
	* Circuit N
* ...
* Connection 2
    * Satellite
	* Circuit 1
	    * Stream 1
		* ...
		* Stream N
	* ...
	* Circuit N

What is notable here, is the presence of a "satellite" process.  This
process is neccessary, as it is responsible for all the TLS traffic.
Without it, the connection process would deadlock itself, as it would
need to process a request while currently processing another request
at the same time.

