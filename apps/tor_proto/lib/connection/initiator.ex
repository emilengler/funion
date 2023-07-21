# SPDX-License-Identifer: ISC

defmodule TorProto.Connection.Initiator do
  @moduledoc """
  Implements the initiator of a Tor protocol connection.
  """
  require Logger
  use GenServer

  @spec valid_cert?(TorCell.Certs.Cert.t(), TorProto.Router.Keys.t()) :: boolean()
  defp valid_cert?(cert, keys) do
    case cert.cert_type do
      :rsa_link -> :public_key.pkix_verify(cert.certificate, keys.rsa_identity)
      :rsa_id -> :public_key.pkix_verify(cert.certificate, keys.rsa_identity)
      :rsa_auth -> :public_key.pkix_verify(cert.certificate, keys.rsa_identity)
      :ed25519_id_signing -> TorCert.Ed25519.is_valid?(cert.certificate, keys.ed25519_identity)
      :ed25519_signing_link -> TorCert.Ed25519.is_valid?(cert.certificate, keys.ed25519_signing)
      :ed25519_signing_auth -> TorCert.Ed25519.is_valid?(cert.certificate, keys.ed25519_signing)
      :rsa_ed25519_cross_cert -> TorCert.RsaEd25519.is_valid?(cert.certificate, keys.rsa_identity)
    end
  end

  @spec valid_certs?(TorCell.Certs.certs(), TorProto.Router.Keys.t()) :: boolean()
  defp valid_certs?(certs, keys) when length(certs) > 0 do
    if valid_cert?(hd(certs), keys) do
      valid_certs?(tl(certs), keys)
    else
      false
    end
  end

  defp valid_certs?(_, _) do
    true
  end

  @spec recv_cell(pid()) :: TorCell.t()
  defp recv_cell(tls_socket) do
    # TODO: Let :dequeue not return :ok if nil
    {:ok, cell} = GenServer.call(tls_socket, :dequeue)

    if cell == nil do
      recv_cell(tls_socket)
    else
      cell
    end
  end

  @spec send_cell(pid(), TorCell.t()) :: :ok
  defp send_cell(tls_socket, cell) do
    :ok = GenServer.call(tls_socket, {:send, cell})
    :ok
  end

  @impl true
  def init(init_args) do
    router = init_args[:router]

    ip =
      if router.ip6 != nil do
        router.ip6
      else
        router.ip4
      end

    {:ok, tls_socket} =
      GenServer.start_link(TorProto.TlsSocket.Client, %{
        host: ip,
        port: router.orport,
        connection: self()
      })

    Logger.debug("Created TLS client process with #{inspect(tls_socket)}")

    send_cell(tls_socket, %TorCell{
      circ_id: 0,
      cmd: :versions,
      payload: %TorCell.Versions{versions: [4]}
    })

    Logger.debug("Sent VERSIONS cell")

    versions = recv_cell(tls_socket)

    %TorCell{circ_id: 0, cmd: :versions, payload: %TorCell.Versions{versions: versions}} =
      versions

    Logger.debug("Received VERSIONS cell with #{inspect(versions)}")
    true = Enum.member?(versions, 4)
    Logger.debug("Using link protocol version 4")

    certs = recv_cell(tls_socket)
    %TorCell{circ_id: 0, cmd: :certs, payload: %TorCell.Certs{certs: certs}} = certs
    Logger.debug("Received CERTS cell")
    true = valid_certs?(certs, router.keys)
    Logger.debug("All certificates are valid")

    auth_challenge = recv_cell(tls_socket)
    %TorCell{circ_id: 0, cmd: :auth_challenge, payload: _} = auth_challenge
    Logger.debug("Received AUTH_CHALLENGE cell")

    netinfo = recv_cell(tls_socket)
    %TorCell{circ_id: 0, cmd: :netinfo, payload: netinfo} = netinfo
    Logger.debug("Received NETINFO cell")
    true = Enum.member?(netinfo.myaddrs, ip)
    Logger.debug("NETINFO cell is valid")

    send_cell(tls_socket, %TorCell{
      circ_id: 0,
      cmd: :netinfo,
      payload: %TorCell.Netinfo{
        time: DateTime.from_unix!(0),
        otheraddr: ip,
        myaddrs: []
      }
    })

    Logger.debug("Sent NETINFO cell")
    Logger.debug("Connection handshake finished")
    Logger.info("Successfully established a connection with #{router.nickname}")

    state = %{}
    {:ok, state}
  end
end
