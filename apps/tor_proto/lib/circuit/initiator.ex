defmodule TorProto.Circuit.Initiator do
  @moduledoc """
  Manages an initiator of a circuit on a channel in the Tor protocol.
  """

  defp gen_secret_input(b, id, x_pub, x_priv, y) do
    # TODO: Remove boilerplate
    # The cryptographic keys as real integers
    <<b::integer-size(32)-unit(8)>> = b
    <<id::integer-size(20)-unit(8)>> = id
    <<x_pub::integer-size(32)-unit(8)>> = x_pub
    <<x_priv::integer-size(32)-unit(8)>> = x_priv
    <<y::integer-size(32)-unit(8)>> = y

    :binary.encode_unsigned(y * x_priv) <>
      :binary.encode_unsigned(b * x_priv) <>
      :binary.encode_unsigned(id) <>
      :binary.encode_unsigned(b) <>
      :binary.encode_unsigned(x_pub) <>
      :binary.encode_unsigned(y) <>
      "ntor-curve25519-sha256-1"
  end

  defp recv_cell() do
    receive do
      {:recv_cell, cell} -> cell
    end
  end

  defp send_cell(cell, parent) do
    send(parent, {:send_cell, cell, self()})

    receive do
      {:send_cell, :ok} -> :ok
    end
  end

  defp handler() do
    :ok
  end

  @doc """
  Creates a fresh circuit on an established channel.

  **DO NOT** use this function on your own!
  Always create circuits through the channels.

  Returns the PID of the new process managing the circuit.
  """
  def init(router, circ_id, parent) do
    # Generate the client-side handshake
    {x_pub, x_priv} = :crypto.generate_key(:ecdh, :x25519, :undefined)
    handshake = router.identity <> router.keys.x25519_ntor <> x_pub

    create2 = %TorCell{
      circ_id: circ_id,
      cmd: :create2,
      payload: %TorCell.Create2{type: :ntor, data: handshake}
    }

    :ok = send_cell(create2, parent)

    created2 = recv_cell()
    %TorCell{circ_id: ^circ_id, cmd: :created2, payload: %TorCell.Created2{data: data}} = created2

    <<server_kp::binary-size(32), data::binary>> = data
    <<auth::binary-size(32), _::binary>> = data

    # TODO: Check if Y is in G^
    # TODO: Compute secrets

    secret_input =
      gen_secret_input(router.keys.x25519_ntor, router.identity, x_pub, x_priv, server_kp)

    handler()
  end
end
