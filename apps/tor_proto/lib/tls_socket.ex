defmodule TorProto.TlsSocket do
  @moduledoc """
  A process managing a TLS socket.
  """

  defp recv_cell(socket, circ_id_len, remaining) do
    try do
      TorCell.fetch(remaining, circ_id_len)
    rescue
      MatchError ->
        {:ok, data} = :ssl.recv(socket, 0)
        recv_cell(socket, circ_id_len, remaining <> :binary.list_to_bin(data))
    end
  end

  defp connect_handler(socket, recv_circ_id_len, send_circ_id_len, remaining) do
    receive do
      {:ip, pid} ->
        {:ok, {ip, _}} = :ssl.peername(socket)
        send(pid, {:ip, ip})
        connect_handler(socket, recv_circ_id_len, send_circ_id_len, remaining)

      {:recv_cell, pid} ->
        {cell, remaining} = recv_cell(socket, recv_circ_id_len, remaining)
        send(pid, {:recv_cell, cell})
        connect_handler(socket, 4, send_circ_id_len, remaining)

      {:send_cell, pid, cell} ->
        :ok = :ssl.send(socket, TorCell.encode(cell, send_circ_id_len))
        send(pid, {:send_cell, :ok})
        connect_handler(socket, recv_circ_id_len, 4, remaining)
    end
  end

  @doc """
  Creates a new process handling a TLS client.

  The messages it accepts are as follows:
  {:ip, pid} -> {:ip, ip}
  {:recv_cell, pid} -> {:recv_cell, cell}
  {:send_cell, pid, cell} -> {:send_cell, :ok}

  Returns the PID of the TlsSocket process.
  """
  def connect(hostname, port) do
    {:ok, socket} = :ssl.connect(hostname, port, active: false)
    spawn(fn -> connect_handler(socket, 2, 2, <<>>) end)
  end
end
