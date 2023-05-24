# SPDX-License-Identifier: ISC

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

  defp ntor_handshake(create, created, router, parent) do
    b = router.keys.x25519_ntor
    id = router.identity
    {x_pk, x_sk} = TorCrypto.Handshake.Ntor.Client.stage1()

    # Create the CREATE2 cell
    # The closure gets the stage2 of the ntor handshake and must return a %TorCell alongside
    # the updated forward context
    {cell, cf} = create.(TorCrypto.Handshake.Ntor.Client.stage2(b, id, x_pk))
    :ok = send_cell(cell, parent)

    # The closure gets the CREATED2/EXTENDED2 cell and must return its data field alongside
    # the updated backward context
    {data, cb} = created.(recv_cell())

    <<y::binary-size(32), data::binary>> = data
    <<auth::binary-size(32), data::binary>> = data

    # TODO: Check if Y is in G^

    secret_input = TorCrypto.Handshake.Ntor.Client.stage3(b, id, x_pk, x_sk, y)
    true = TorCrypto.Handshake.Ntor.Client.is_valid?(secret_input, auth, b, id, x_pk, y)
    keys = TorCrypto.Handshake.Ntor.derive_keys(secret_input)

    {
      %{
        kf: keys.kf,
        kb: keys.kb,
        cf: TorCrypto.Digest.init(keys.df),
        cb: TorCrypto.Digest.init(keys.db)
      },
      cf,
      cb
    }
  end

  defp handler(circ_id, parent, state) do
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

        extend2 = fn data ->
          cell = %TorCell.RelayCell{
            cmd: :extend2,
            stream_id: 0,
            data: %TorCell.RelayCell.Extend2{specs: specs, type: :ntor, data: data}
          }

          cf = List.last(state[:hops]).cf
          kfs = Enum.map(state[:hops], fn x -> x.kf end)
          {onion_skin, cf} = TorCell.RelayCell.encrypt(cell, cf, kfs)

          {
            %TorCell{
              circ_id: circ_id,
              cmd: :relay_early,
              payload: %TorCell.RelayEarly{onion_skin: onion_skin}
            },
            cf
          }
        end

        extended2 = fn cell ->
          %TorCell{
            circ_id: ^circ_id,
            cmd: :relay,
            payload: %TorCell.Relay{onion_skin: onion_skin}
          } = cell

          cb = List.last(state[:hops]).cb
          kbs = Enum.map(state[:hops], fn x -> x.kb end)
          {true, cell, cb} = TorCell.RelayCell.decrypt(onion_skin, cb, kbs)

          %TorCell.RelayCell{
            cmd: :extended2,
            stream_id: 0,
            data: %TorCell.RelayCell.Extended2{data: data}
          } = cell

          {data, cb}
        end

        {next_hop, cf, cb} = ntor_handshake(extend2, extended2, router, parent)

        # Update the state
        hop = List.last(state[:hops])
        hop = %{kf: hop.kf, kb: hop.kb, cf: cf, cb: cb}
        state = Map.replace!(state, :hops, List.replace_at(state[:hops], -1, hop))
        state = Map.replace!(state, :hops, state[:hops] ++ [next_hop])

        send(pid, {:extend, :ok})
        handler(circ_id, parent, state)
    end
  end

  @doc """
  Creates a fresh circuit on an established channel.

  **DO NOT** use this function on your own!
  Always create circuits through the channels.

  Returns the PID of the new process managing the circuit.
  """
  def init(router, circ_id, parent) do
    create2 = fn data ->
      {
        %TorCell{
          circ_id: circ_id,
          cmd: :create2,
          payload: %TorCell.Create2{type: :ntor, data: data}
        },
        nil
      }
    end

    created2 = fn cell ->
      %TorCell{circ_id: ^circ_id, cmd: :created2, payload: %TorCell.Created2{data: data}} = cell
      {data, nil}
    end

    {hop, nil, nil} = ntor_handshake(create2, created2, router, parent)
    state = %{hops: [hop]}

    handler(circ_id, parent, state)
  end
end
