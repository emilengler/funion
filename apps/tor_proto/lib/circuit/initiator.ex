defmodule TorProto.Circuit.Initiator do
  @moduledoc """
  Manages an initiator of a circuit on a channel in the Tor protocol.
  """

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

  defp handler(router, circ_id, parent, state) do
    :ok
  end

  @doc """
  Creates a fresh circuit on an established channel.

  **DO NOT** use this function on your own!
  Always create circuits through the channels.

  Returns the PID of the new process managing the circuit.
  """
  def init(router, circ_id, parent) do
    b = router.keys.x25519_ntor
    id = router.identity
    {x_pk, x_sk} = TorCrypto.Handshake.Ntor.Client.stage1()

    create2 = %TorCell{
      circ_id: circ_id,
      cmd: :create2,
      payload: %TorCell.Create2{
        type: :ntor,
        data: TorCrypto.Handshake.Ntor.Client.stage2(b, id, x_pk)
      }
    }

    :ok = send_cell(create2, parent)

    created2 = recv_cell()
    %TorCell{circ_id: ^circ_id, cmd: :created2, payload: %TorCell.Created2{data: data}} = created2

    <<y::binary-size(32), data::binary>> = data
    <<auth::binary-size(32), _::binary>> = data

    # TODO: Check if Y is in G^

    secret_input = TorCrypto.Handshake.Ntor.Client.stage3(b, id, x_pk, x_sk, y)
    true = TorCrypto.Handshake.Ntor.Client.is_valid?(secret_input, auth, b, id, x_pk, y)
    keys = TorCrypto.Handshake.Ntor.derive_keys(secret_input)

    state = %{
      keys: keys,
      digest_forward: TorCrypto.Digest.init(keys.df),
      digest_backward: TorCrypto.Digest.init(keys.db)
    }

    handler(router, circ_id, parent, state)
  end
end
