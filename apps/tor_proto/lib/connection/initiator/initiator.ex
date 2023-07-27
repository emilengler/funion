# SPDX-License-Identifier: ISC

defmodule TorProto.Connection.Initiator do
  @moduledoc """
  Implements a connection of the Tor protocol.
  """

  @type t :: pid()

  ## Client API

  @spec poll(t()) :: :ok | {:error, term()}
  def poll(connection) do
    :ok = GenServer.cast(connection, :poll)
  end
end
