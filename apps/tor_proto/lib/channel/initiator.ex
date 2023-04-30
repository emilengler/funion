defmodule TorProto.Channel.Initiator do
  @moduledoc """
  Manages an initiator on a channel in the Tor protocol.

  TODO: Use GenServer for this (once there are actual commands)
  """

  defp gen_versions_cell() do
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

  defp gen_circ_id(circ_ids) do
    # Set the MSB to 1
    circ_id = Bitwise.bor(2 ** 31, Enum.random(1..(2 ** 32 - 1)))

    # Check if the circ_id already exists
    if Map.fetch(circ_ids, circ_id) != :error do
      gen_circ_id(circ_ids)
    else
      circ_id
    end
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

  defp handler(router, socket, state) do
    receive do
      {:create, pid} ->
        parent = self()
        circ_id = gen_circ_id(state[:circ_ids])

        circuit =
          spawn_link(fn ->
            TorProto.Circuit.Initiator.init(router, circ_id, parent)
          end)

        state = %{circ_ids: Map.put(state[:circ_ids], circ_id, circuit)}
        send(pid, {:create, circuit})
        handler(router, socket, state)

      {:recv_cell, cell} ->
        if cell.circ_id == 0 do
          raise "TODO"
        else
          send(Map.fetch!(state[:circ_ids], cell.circ_id), {:recv_cell, cell})
          handler(router, socket, state)
        end

      {:send_cell, cell, pid} ->
        # Dirty hack :^)
        if pid != Map.fetch!(state[:circ_ids], cell.circ_id) do
          raise MatchError
        end

        send_cell(socket, cell)
        send(pid, {:send_cell, :ok})
        handler(router, socket, state)
    end
  end

  @doc """
  Creates a fresh TLS connection and initiates a channel on it.
  """
  def init(router) do
    ip =
      if router.ip6 != nil do
        router.ip6
      else
        router.ip4
      end

    parent = self()
    socket = spawn_link(fn -> TorProto.TlsSocket.Client.init(ip, router.orport, parent) end)

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

    handler(router, socket, %{
      circ_ids: %{}
    })
  end
end
