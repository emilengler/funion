defmodule TlsSocket do
  @moduledoc """
  A process managing a TLS socket.
  """

  defp connect_handler(socket) do
    receive do
      {:ip, pid} ->
        send(pid, fn ->
          {:ok, {ip, _}} = :ssl.peername(socket)
          ip
        end)

        connect_handler(socket)
    end
  end

  def connect(hostname, port) do
    {:ok, socket} = :ssl.connect(hostname, port, active: false)
    connect_handler(socket)
  end
end
