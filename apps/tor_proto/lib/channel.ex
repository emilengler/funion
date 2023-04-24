defmodule TorProto.Channel do
  @moduledoc """
  A manager for the Channel of the Tor protocol.
  """

  def gen_versions_cell() do
    %TorCell{
      circ_id: 0,
      cmd: :versions,
      payload: %TorCell.Versions{versions: [4]}
    }
  end

  defp gen_netinfo_cell(ip) do
    %TorCell{
      circ_id: 0,
      cmd: :netinfo,
      payload: %TorCell.Netinfo{
        time: DateTime.from_unix!(0),
        otheraddr: ip,
        myaddrs: []
      }
    }
  end

  defp get_ip(socket) do
    send(socket, {:get_ip})

    receive do
      {:get_ip, ip} -> ip
    end
  end

  defp recv_cell() do
    receive do
      {:recv_cell, cell} -> cell
    end
  end

  defp send_cell(socket, cell) do
    send(socket, {:send_cell, cell})

    receive do
      {:send_cell, :ok} -> :ok
    end
  end

  defp initiator_init(socket) do
    # TODO: Validate the cells

    :ok = send_cell(socket, gen_versions_cell())

    versions = recv_cell()
    %TorCell{circ_id: 0, cmd: :versions, payload: %TorCell.Versions{versions: _}} = versions

    certs = recv_cell()
    %TorCell{circ_id: 0, cmd: :certs, payload: _} = certs

    auth_challenge = recv_cell()
    %TorCell{circ_id: 0, cmd: :auth_challenge, payload: _} = auth_challenge

    netinfo = recv_cell()
    %TorCell{circ_id: 0, cmd: :netinfo, payload: _} = netinfo

    # Send a NETINFO TorCell
    :ok = send_cell(socket, gen_netinfo_cell(get_ip(socket)))

    :ok
  end

  defp initiator_handler() do
    :ok
  end

  @doc """
  Initiates new channel manager in the current process.
  """
  def initiator(hostname, port) do
    parent = self()
    socket = spawn_link(fn -> TorProto.TlsSocket.client(hostname, port, parent) end)
    initiator_init(socket)
    initiator_handler()
    :ok
  end
end
