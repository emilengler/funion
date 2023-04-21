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

  defp recv_cell() do
    cell =
      receive do
        {:cell, cell} -> cell
      end

    %TorCell{circ_id: _, cmd: _, payload: _} = cell
    cell
  end

  defp initiator_init(responder) do
    # TODO: Validate the cells
    # TODO: Do something with padding cells

    send(responder, {:cell, gen_versions_cell()})

    versions = recv_cell()
    %TorCell{circ_id: 0, cmd: :versions, payload: %TorCell.Versions{versions: [4]}} = versions

    certs = recv_cell()
    %TorCell{circ_id: 0, cmd: :certs, payload: _} = certs

    auth_challenge = recv_cell()
    %TorCell{circ_id: 0, cmd: :auth_challenge, payload: _} = auth_challenge

    netinfo = recv_cell()
    %TorCell{circ_id: 0, cmd: :netinfo, payload: _} = netinfo

    send(responder, :ip)

    ip =
      receive do
        {:ip, ip} -> ip
      end

    send(responder, {:cell, gen_netinfo_cell(ip)})

    :ok
  end

  defp initiator_handler() do
    :ok
  end

  @doc """
  Inititates a new channel in a new process communicating with a TorProto.Socket process.

  Returns the PID of the new channel process.
  """
  def inititator(responder) do
    initiator_init(responder)
    spawn(initiator_handler())
  end
end
