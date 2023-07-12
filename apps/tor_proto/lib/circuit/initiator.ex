# SPDX-License-Identifier: ISC

defmodule TorProto.Circuit.Initiator do
  @moduledoc """
  Manages an initiator of a circuit on a channel in the Tor protocol.

  TODO: Do the handshakes in some sort of a separate function.
  """

  defp gen_stream_id(streams) do
    stream_id = Enum.random(1..(2 ** 16 - 1))

    if Map.fetch(streams, stream_id) == :error do
      stream_id
    else
      gen_stream_id(streams)
    end
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

  defp ntor_handshake(create, created, router, parent) do
    b = router.keys.x25519_ntor
    id = router.identity
    {x_pk, x_sk} = TorCrypto.Handshake.Ntor.Client.stage1()

    # Create the CREATE2 cell
    # The closure gets the stage2 of the ntor handshake and must return a %TorCell alongside
    # the updated forward context
    {cell, df} = create.(TorCrypto.Handshake.Ntor.Client.stage2(b, id, x_pk))
    :ok = send_cell(cell, parent)

    # The closure gets the CREATED2/EXTENDED2 cell and must return its data field alongside
    # the updated backward context
    {data, db} = created.(recv_cell())

    <<y::binary-size(32), data::binary>> = data
    <<auth::binary-size(32), data::binary>> = data

    # TODO: Check if Y is in G^

    secret_input = TorCrypto.Handshake.Ntor.Client.stage3(b, id, x_pk, x_sk, y)
    true = TorCrypto.Handshake.Ntor.Client.is_valid?(secret_input, auth, b, id, x_pk, y)
    keys = TorCrypto.Handshake.Ntor.derive_keys(secret_input)

    {
      %{
        kf: TorCrypto.OnionSkin.init(keys.kf, true),
        kb: TorCrypto.OnionSkin.init(keys.kb, false),
        df: TorCrypto.Digest.init(keys.df),
        db: TorCrypto.Digest.init(keys.db)
      },
      df,
      db
    }
  end

  defp handler(circ_id, parent, state) do
    receive do
      {:connect, host, port, pid} ->
        ourself = self()
        stream_id = gen_stream_id(state[:streams])

        stream =
          spawn_link(fn -> TorProto.Stream.Initiator.init(host, port, stream_id, ourself, pid) end)

        send(pid, {:connect, stream})

        state = Map.replace!(state, :streams, Map.put(state[:streams], stream_id, stream))
        handler(circ_id, parent, state)

      {:end, pid} ->
        if map_size(state[:streams]) != 0 do
          send(pid, {:end, :error})
          handler(circ_id, parent, state)
        else
          destroy = %TorCell{
            circ_id: circ_id,
            cmd: :destroy,
            payload: %TorCell.Destroy{reason: :finished}
          }

          :ok = send_cell(destroy, parent)
          send(parent, {:end_circuit, circ_id, self()})

          receive do
            {:end_circuit, :ok} -> nil
          end

          send(pid, {:end, :ok})
        end

      {:end_stream, stream_id, pid} ->
        true = state[:streams][stream_id] == pid
        send(pid, {:end_stream, :ok})

        state = Map.replace!(state, :streams, Map.delete(state[:streams], stream_id))
        handler(circ_id, parent, state)

      {:extend, router, pid} ->
        # Generate the specs field
        specs = [
          %TorCell.RelayCell.Extend2.Spec{
            lstype: :tls_over_tcp4,
            lspec: %TorCell.RelayCell.Extend2.Spec.TlsOverTcp4{
              ip: router.ip4,
              port: router.orport
            }
          },
          %TorCell.RelayCell.Extend2.Spec{
            lstype: :legacy_identity,
            lspec: %TorCell.RelayCell.Extend2.Spec.LegacyIdentity{fingerprint: router.identity}
          },
          %TorCell.RelayCell.Extend2.Spec{
            lstype: :ed25519_identity,
            lspec: %TorCell.RelayCell.Extend2.Spec.Ed25519Identity{
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
                  lstype: :tls_over_tcp6,
                  lspec: %TorCell.RelayCell.Extend2.Spec.TlsOverTcp6{
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
            data: %TorCell.RelayCell.Extend2{specs: specs, htype: :ntor, hdata: data}
          }

          df = List.last(state[:hops]).df
          kfs = Enum.map(state[:hops], fn x -> x.kf end)
          {onion_skin, df} = TorCell.RelayCell.encrypt(cell, kfs, df)

          {
            %TorCell{
              circ_id: circ_id,
              cmd: :relay_early,
              payload: %TorCell.RelayEarly{onion_skin: onion_skin}
            },
            df
          }
        end

        extended2 = fn cell ->
          %TorCell{
            circ_id: ^circ_id,
            cmd: :relay,
            payload: %TorCell.Relay{onion_skin: onion_skin}
          } = cell

          db = List.last(state[:hops]).db
          kbs = Enum.map(state[:hops], fn x -> x.kb end)
          {true, cell, db} = TorCell.RelayCell.decrypt(onion_skin, kbs, db)

          %TorCell.RelayCell{
            cmd: :extended2,
            stream_id: 0,
            data: %TorCell.RelayCell.Extended2{hdata: data}
          } = cell

          {data, db}
        end

        {next_hop, df, db} = ntor_handshake(extend2, extended2, router, parent)

        # Update the state
        hop = List.last(state[:hops])
        hop = %{kf: hop.kf, kb: hop.kb, df: df, db: db}
        state = Map.replace!(state, :hops, List.replace_at(state[:hops], -1, hop))
        state = Map.replace!(state, :hops, state[:hops] ++ [next_hop])

        send(pid, {:extend, :ok})
        handler(circ_id, parent, state)

      {:recv_cell, cell} ->
        %TorCell{circ_id: ^circ_id, cmd: cmd, payload: payload} = cell

        state =
          case cmd do
            :relay ->
              kbs = Enum.map(state[:hops], fn x -> x.kb end)
              db = List.last(state[:hops]).db
              {true, relay_cell, db} = TorCell.RelayCell.decrypt(payload.onion_skin, kbs, db)

              send(
                Map.fetch!(state[:streams], relay_cell.stream_id),
                {:recv_relay_cell, relay_cell}
              )

              hop = List.last(state[:hops])
              hop = %{kf: hop.kf, kb: hop.kb, df: hop.df, db: db}
              Map.replace!(state, :hops, List.replace_at(state[:hops], -1, hop))
          end

        handler(circ_id, parent, state)

      {:send_relay_cell, relay_cell, pid} ->
        kfs = Enum.map(state[:hops], fn x -> x.kf end)
        df = List.last(state[:hops]).df
        {onion_skin, df} = TorCell.RelayCell.encrypt(relay_cell, kfs, df)

        cell = %TorCell{
          circ_id: circ_id,
          cmd: :relay,
          payload: %TorCell.Relay{onion_skin: onion_skin}
        }

        :ok = send_cell(cell, parent)

        hop = List.last(state[:hops])
        hop = %{kf: hop.kf, kb: hop.kb, df: df, db: hop.db}
        state = Map.replace!(state, :hops, List.replace_at(state[:hops], -1, hop))

        send(pid, {:send_relay_cell, :ok})

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
          payload: %TorCell.Create2{htype: :ntor, hdata: data}
        },
        nil
      }
    end

    created2 = fn cell ->
      %TorCell{circ_id: ^circ_id, cmd: :created2, payload: %TorCell.Created2{hdata: data}} = cell
      {data, nil}
    end

    {hop, nil, nil} = ntor_handshake(create2, created2, router, parent)
    state = %{hops: [hop], streams: %{}}

    handler(circ_id, parent, state)
  end
end
