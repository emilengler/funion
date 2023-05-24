defmodule TorProto.Circuit.Initiator do
  @moduledoc """
  Manages an initiator of a circuit on a channel in the Tor protocol.

  TODO: Do the handshakes in some sort of a separate function.
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
    receive do
      {:extend, router, pid} ->
        # Generate the specs field
        specs = [
          %TorCell.RelayCell.Extend2.Spec{
            type: :tls_over_tcp4,
            spec: %TorCell.RelayCell.Extend2.Spec.TlsOverTcp4{
              ip: router.ip4,
              port: router.orport
            }
          },
          %TorCell.RelayCell.Extend2.Spec{
            type: :legacy_identity,
            spec: %TorCell.RelayCell.Extend2.Spec.LegacyIdentity{fingerprint: router.identity}
          },
          %TorCell.RelayCell.Extend2.Spec{
            type: :ed25519_identity,
            spec: %TorCell.RelayCell.Extend2.Spec.Ed25519Identity{
              fingerprint: router.keys.ed25519_identity
            }
          }
        ]

        # Append a :tls_over_tcp6 spec if this field is set in router
        specs =
          if router.ip6 == nil do
            specs
          else
            specs ++
              [
                %TorCell.RelayCell.Extend2.Spec{
                  type: :tls_over_tcp6,
                  spec: %TorCell.RelayCell.Extend2.Spec.TlsOverTcp6{
                    ip: router.ip6,
                    port: router.orport
                  }
                }
              ]
          end

        # Prepare the ntor handshake
        {x_pk, x_sk} = TorCrypto.Handshake.Ntor.Client.stage1()
        b = router.keys.x25519_ntor
        id = router.identity

        # Generate the cell with the appropriate ntor handshake
        extend2 = %TorCell.RelayCell{
          cmd: :extend2,
          stream_id: 0,
          data: %TorCell.RelayCell.Extend2{
            specs: specs,
            type: :ntor,
            data: TorCrypto.Handshake.Ntor.Client.stage2(b, id, x_pk)
          }
        }

        # Get the onion skin of the extend2 cell
        cf = state[:context_forward]
        keys_f = Enum.map(state[:keys], fn x -> x.kf end)
        {onion_skin, cf} = TorCell.RelayCell.encrypt(extend2, cf, keys_f)

        # Place the extend2 cell into a TorCell
        extend2 = %TorCell{
          circ_id: circ_id,
          cmd: :relay_early,
          payload: %TorCell.RelayEarly{onion_skin: onion_skin}
        }

        :ok = send_cell(extend2, parent)

        # Receive an EXTENDED2 TorCell
        extended2 = recv_cell()

        cb = state[:context_backward]
        keys_b = Enum.map(state[:keys], fn x -> x.kb end)

        {true, extended2, cb} =
          TorCell.RelayCell.decrypt(extended2.payload.onion_skin, cb, keys_b)

        %TorCell.RelayCell{cmd: :extended2, data: %TorCell.RelayCell.Extended2{data: data}} =
          extended2

        # Finalize the handshake
        <<y::binary-size(32), data::binary>> = data
        <<auth::binary-size(32), _::binary>> = data

        # TODO: Check if Y is in G^

        secret_input = TorCrypto.Handshake.Ntor.Client.stage3(b, id, x_pk, x_sk, y)
        true = TorCrypto.Handshake.Ntor.Client.is_valid?(secret_input, auth, b, id, x_pk, y)
        keys = TorCrypto.Handshake.Ntor.derive_keys(secret_input)

        send(pid, {:extend, :ok})

        # TODO: Update the state
    end
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
      keys: [keys],
      context_forward: TorCrypto.Digest.init(keys.df),
      context_backward: TorCrypto.Digest.init(keys.db)
    }

    handler(router, circ_id, parent, state)
  end
end
