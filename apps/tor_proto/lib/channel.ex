defmodule TorProto.Channel do
  @moduledoc """
  Implements the Channel (connection) of the Tor protocol.
  """

  defp gen_versions_cell() do
    %TorCell{
      circ_id: 0,
      cmd: :versions,
      payload: %TorCell.Versions{
        versions: [4]
      }
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

  defp recv_cell(responder) do
    send(responder, {:recv_cell, self()})

    receive do
      {:recv_cell, cell} -> cell
    end
  end

  defp send_cell(responder, cell) do
    send(responder, {:send_cell, self(), cell})

    receive do
      {:send_cell, :ok} -> :ok
    end
  end

  defp initiator_init(responder) do
    # TODO: Validate the cells
    # TODO: Do something with padding cells

    send_cell(responder, gen_versions_cell())

    versions = recv_cell(responder)
    %TorCell{circ_id: 0, cmd: :versions, payload: %TorCell.Versions{versions: _}} = versions

    certs = recv_cell(responder)
    %TorCell{circ_id: 0, cmd: :certs, payload: _} = certs

    auth_challenge = recv_cell(responder)
    %TorCell{circ_id: 0, cmd: :auth_challenge, payload: _} = auth_challenge

    netinfo = recv_cell(responder)
    %TorCell{circ_id: 0, cmd: :netinfo, payload: _} = netinfo

    send(responder, {:ip, self()})

    ip =
      receive do
        {:ip, ip} -> ip
      end

    send_cell(responder, gen_netinfo_cell(ip))

    :ok
  end

  defp initiator_handler() do
    :ok
  end

  @doc """
  Inititates a new channel in a new process communicating with a TorProto.TlsSocket process.

  Returns the PID of the new channel process.
  """
  def inititator(responder) do
    initiator_init(responder)
    spawn(fn -> initiator_handler() end)
  end
end
