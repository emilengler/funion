defmodule TorProto.Channel do
  @moduledoc """
  Implements the Channel (connection) of the Tor protocol.
  """
  defstruct socket: nil,
            version: nil

  defp read_cell(socket, remaining \\ <<>>) do
    {:ok, data} = :ssl.recv(socket, 0)
    data = remaining <> data

    try do
      TorCell.fetch(data)
    rescue
      MatchError -> read_cell(socket, remaining <> data)
    end
  end
end
