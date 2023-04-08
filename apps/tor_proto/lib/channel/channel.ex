defmodule TorProto.Channel do
  @moduledoc """
  Implements the Channel (connection) of the Tor protocol.
  """
  defstruct socket: nil,
            version: nil

  defp gen_versions_cell() do
    TorCell.encode(
      %TorCell{
        circ_id: 0,
        cmd: :versions,
        payload: TorCell.Versions.encode(%TorCell.Versions{versions: [3, 4]})
      },
      2
    )
  end

  defp recv_cell(socket, circ_id_len, remaining) do
    try do
      TorCell.fetch(remaining, circ_id_len)
    rescue
      MatchError ->
        {:ok, new} = :ssl.recv(socket, 0, 5000)
        recv_cell(socket, circ_id_len, remaining <> :binary.list_to_bin(new))
    end
  end

  @doc """
  Initiates a new channel on a connected TLS socket.

  Returns the internal represenation of a Channel.
  """
  def initiate(socket) do
    :ok = :ssl.send(socket, gen_versions_cell())

    {versions_cell, remaining} = recv_cell(socket, 2, <<>>)
    {certs_cell, remaining} = recv_cell(socket, 4, remaining)
    {auth_challenge_cell, remaining} = recv_cell(socket, 4, remaining)
    {netinfo_cell, remaining} = recv_cell(socket, 4, remaining)

    nil
  end
end
