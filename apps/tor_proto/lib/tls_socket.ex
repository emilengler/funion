defmodule TorProto.TlsSocket do
  @moduledoc """
  A process managing a TLS socket.
  """

  defp recv_cells(cells, state) do
    try do
      {cell, remaining} = TorCell.fetch(state[:remaining], state[:recv_circ_id_len])
      state = Map.replace!(state, :recv_circ_id_len, 4)
      state = Map.replace!(state, :remaining, remaining)
      recv_cells(cells ++ [cell], state)
    rescue
      MatchError -> {cells, state}
    end
  end

  defp client_handler(socket, parent, state) do
    receive do
      {:get_ip} ->
        {:ok, {ip, _}} = :ssl.peername(socket)
        send(parent, {:get_ip, ip})
        client_handler(socket, parent, state)

      {:send_cell, cell} ->
        :ok = :ssl.send(socket, TorCell.encode(cell, state[:send_circ_id_len]))
        state = Map.replace!(state, :send_circ_id_len, 4)
        send(parent, {:send_cell, :ok})
        client_handler(socket, parent, state)

      {:ssl, ^socket, data} ->
        state = Map.replace!(state, :remaining, state[:remaining] <> :binary.list_to_bin(data))
        {cells, state} = recv_cells([], state)
        Enum.map(cells, fn x -> send(parent, {:recv_cell, x}) end)
        client_handler(socket, parent, state)
    end
  end

  @doc """
  Creates a new process handling a TLS client operating directly on TorCells.

  On incoming TorCells, this process sends the following message:
  {:recv_cell, cells}

  The messages it acceps are as follows:
  {:get_ip} -> {:get_ip, ip}
  {:send_cell, cell} -> {:send_cell, :ok}

  Returns the PID of the TlsSocket process.
  """
  def client(hostname, port, parent) do
    # TODO: Consider using a struct instead of a raw map
    spawn(fn ->
      {:ok, socket} = :ssl.connect(hostname, port, active: true)

      client_handler(socket, parent, %{
        :recv_circ_id_len => 2,
        :send_circ_id_len => 2,
        :remaining => <<>>
      })
    end)
  end
end
