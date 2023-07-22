# SPDX-License-Identifier: ISC

defmodule TorProto.Circuit.Initiator do
  @moduledoc """
  Implements a Tor circuit using GenServer.
  """
  require Logger
  use GenServer

  @type create2 :: (binary() -> TorCell.t())
  @type created2 :: (TorCell.t() -> binary())

  @spec ntor(create2(), created2(), TorProto.Router.t(), pid()) ::
          {%{
             kf: TorCrypto.OnionStream.t(),
             kb: TorCrypto.OnionStream.t(),
             df: TorCrypto.Digest.t(),
             db: TorCrypto.Digest.t()
           }, TorCrypto.Digest.t(), TorCrypto.Digest.t()}
  defp ntor(create2, created2, router, connection) do
    b = router.keys.x25519_ntor
    id = router.identity
    {x_pk, x_sk} = TorCrypto.Handshake.Ntor.Client.stage1()

    # Create the CREATED2 cell
    # The closure gets the handshake data of the ntor handshake and must
    # return a TorCell alongside the updated forward digest.
    {cell, df} = create2.(TorCrypto.Handshake.Ntor.Client.stage2(b, id, x_pk))
    send_cell(connection, cell)
    Logger.debug("Sent circuit handshake")

    # The closure gets the CREATED2 cell and must returns its handshake
    # data alongside the updated backward digest.
    cell = recv_cell(connection)
    {hdata, db} = created2.(cell)
    Logger.debug("Received circuit handshake reply")

    remaining = hdata
    <<y::binary-size(32), remaining::binary>> = remaining
    <<auth::binary-size(32), _::binary>> = remaining

    # TODO: Check if Y is in G.
    secret_input = TorCrypto.Handshake.Ntor.Client.stage3(b, id, x_pk, x_sk, y)

    true = TorCrypto.Handshake.Ntor.Client.is_valid?(secret_input, auth, b, id, x_pk, y)
    Logger.debug("Circuit handshake is valid")

    keys = TorCrypto.Handshake.Ntor.derive_keys(secret_input)

    {
      %{
        kf: TorCrypto.OnionStream.init(keys.kf, true),
        kb: TorCrypto.OnionStream.init(keys.kb, true),
        df: TorCrypto.Digest.init(keys.df),
        db: TorCrypto.Digest.init(keys.db)
      },
      df,
      db
    }
  end

  @spec recv_cell(pid()) :: TorCell.t()
  defp recv_cell(connection) do
    # TODO: Let :dequeue not return :ok if nil
    {:ok, cell} = GenServer.call(connection, :dequeue)

    if cell == nil do
      recv_cell(connection)
    else
      cell
    end
  end

  @spec send_cell(pid(), TorCell.t()) :: :ok
  defp send_cell(connection, cell) do
    :ok = GenServer.call(connection, {:send, cell})
    :ok
  end

  @impl true
  def init(init_args) do
    circ_id = init_args[:circ_id]
    connection = init_args[:connection]
    router = init_args[:router]

    # The initialization has to take place in an asynchronous fashion,
    # because we need to interact with the connection process during
    # our true initialization.
    GenServer.cast(self(), {:init, circ_id, connection, router})

    {:ok, nil}
  end

  @impl true
  def handle_cast({:init, circ_id, connection, router}, state) do
    nil = state

    create2 = fn hdata ->
      {
        %TorCell{
          circ_id: circ_id,
          cmd: :create2,
          payload: %TorCell.Create2{htype: :ntor, hdata: hdata}
        },
        nil
      }
    end

    created2 = fn created2 ->
      %TorCell{circ_id: ^circ_id, cmd: :created2, payload: %TorCell.Created2{hdata: hdata}} =
        created2

      {hdata, nil}
    end

    {hop, nil, nil} = ntor(create2, created2, router, connection)
    Logger.debug("Circuit handshake finished")

    Logger.info("Successfully established a circuit with #{router.nickname}")

    state = %{circ_id: circ_id, connection: connection, hops: [hop]}
    {:noreply, state}
  end
end
