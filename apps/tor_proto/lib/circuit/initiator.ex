# SPDX-License-Identifier: ISC

defmodule TorProto.Circuit.Initiator do
  @moduledoc """
  Implements a circuit of the Tor protocol.
  """

  @type t :: pid()

  require Logger
  use GenServer

  ## GenServer Callbacks

  @impl true
  def init(init_arg) do
    {:ok, nil}
  end

  @impl true
  def terminate(:normal, state) do
    :normal
  end

  @impl true
  def handle_call(:dequeue, from, state) do
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:create, host, port}, _from, state) do
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:destroy, stream_id}, from, state) do
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:extend, router}, _from, state) do
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:poll, pid}, state) do
    {:noreply, state}
  end

  @impl true
  def handle_cast({:send_cell, cell, pid}, state) do
    {:noreply, state}
  end

  ## Client API

  @doc """
  Starts a circuit on an existing connection.

  This function should only be called from the accompanying connection process.
  """
  @spec start_link(TorCell.circ_id(), TorProto.Connection.Initiator.t(), TorProto.Router.t()) ::
          :ok | {:error, term()}
  def start_link(circ_id, connection, router) do
    {:ok, circuit} =
      GenServer.start_link(__MODULE__, %{circ_id: circ_id, connection: connection, router: router})

    {:ok, circuit}
  end

  @doc """
  Terminates a circuit, including all its associated streams.
  """
  @spec stop(t()) :: :ok | {:error, term()}
  def stop(server) do
    # :ok = GenServer.stop(circuit, :normal)
    :ok
  end

  @doc """
  Dequeues a cell from the FIFO.

  This function can only be called from stream processes.
  A violation against this will result in a termination of the process.
  """
  @spec dequeue(t()) :: {:ok, TorCell.t()} | {:error, term()}
  def dequeue(server) do
    GenServer.call(server, :dequeue)
  end

  @doc """
  Creates a new stream on the circuit with a random circuit ID.
  """
  @spec create(t(), :inet.hostname(), :inet.port_number()) :: :ok | {:error, term()}
  def create(server, host, port) do
    GenServer.call(server, {:create, host, port})
  end

  @doc """
  Destroys a stream on the circuit.

  This function can only be called from stream processes.
  A violation against this will result in a termination of the process.
  """
  @spec destroy(t(), TorCell.RelayCell.stream_id()) :: :ok | {:error, term()}
  def destroy(server, stream_id) do
    GenServer.call(server, {:destroy, stream_id})
  end

  @doc """
  Extends a circuit by another hop.
  """
  @spec extend(t(), TorProto.Router.t()) :: :ok | {:error, term()}
  def extend(server, router) do
    GenServer.call(server, {:extend, router})
  end

  @doc """
  Tells the GenServer that a new cell is available from its connection.

  This function can only be called by the connection process.
  A violation against this will result in a termination of the process.
  """
  @spec poll(t()) :: :ok | {:error, term()}
  def poll(server) do
    GenServer.cast(server, {:poll, self()})
  end

  @doc """
  Sends a cell out of the circuit.

  This function can only be called from stream processes.
  A violation against this will result in a termination of the process.
  """
  @spec send_cell(t(), TorCell.RelayCell.t()) :: :ok | {:error, term()}
  def send_cell(server, cell) do
    GenServer.cast(server, {:send_cell, cell, self()})
  end
end
