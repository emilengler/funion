# SPDX-License-Identifier: ISC

defmodule TorProto.Circuit.Initiator do
  @moduledoc """
  Implements a circuit of the Tor protocol.
  """

  @type t :: pid()

  ## Client API

  @spec stop(t()) :: :ok | {:error, term()}
  def stop(circuit) do
    # :ok = GenServer.stop(circuit, :normal)
    :ok
  end

  @spec poll(t()) :: :ok | {:error, term()}
  def poll(circuit) do
    :ok = GenServer.cast(circuit, :poll)
  end
end
