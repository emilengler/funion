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
        payload: %TorCell.Versions{versions: [4]}
      },
      2
    )
  end

  defp gen_netinfo_cell(socket) do
    {:ok, {ip, _}} = :ssl.peername(socket)

    TorCell.encode(%TorCell{
      circ_id: 0,
      cmd: :netinfo,
      payload: %TorCell.Netinfo{
        time: DateTime.from_unix!(0),
        otheraddr: ip,
        myaddrs: []
      }
    })
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
  Initiates a new channel.

  Returns the internal represenation of a channel.
  """
  def initiate(hostname, port) do
    {:ok, socket} = :ssl.connect(hostname, port, active: false)
    TorProto.Channel.initiate(socket)
  end

  @doc """
  Initiates a new channel on an already established TLS socket.

  Returns the internal representation of a channel.

  TODO: Consider making this function private, as it effectively only
  serves testing purposes.
  """
  def initiate(socket) do
    :ok = :ssl.send(socket, gen_versions_cell())

    {versions_cell, remaining} = recv_cell(socket, 2, <<>>)
    # TODO: Negotiate versions
    {certs_cell, remaining} = recv_cell(socket, 4, remaining)
    {auth_challenge_cell, remaining} = recv_cell(socket, 4, remaining)
    {netinfo_cell, remaining} = recv_cell(socket, 4, remaining)

    # TODO: Validate the cells
    # TODO: Perform an authentication

    :ok = :ssl.send(socket, gen_netinfo_cell(socket))

    %TorProto.Channel{
      socket: socket,
      version: 4
    }
  end

  def close(chan) do
    :ok = :ssl.close(chan.socket)
  end
end
