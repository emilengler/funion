# SPDX-License-Identifier: ISC

defmodule TorProto.PidFifos do
  @moduledoc """
  Implements a structure, in which each PID has their own FIFO.
  """
  @type t :: map()

  @doc """
  Initializes the CellFifo.
  """
  @spec init() :: t()
  def init() do
    %{}
  end

  @doc """
  Dequeues a cell from the start of a PID's FIFO.
  """
  @spec dequeue(t(), pid()) :: {t(), TorCell.t() | nil}
  def dequeue(fifos, pid) do
    fifo = Map.get(fifos, pid)

    if fifo == nil || :queue.len(fifo) == 0 do
      {fifos, nil}
    else
      {{:value, cell}, fifo} = :queue.out(fifo)

      fifos =
        if :queue.len(fifo) == 0 do
          Map.delete(fifos, pid)
        else
          Map.put(fifos, pid, fifo)
        end

      {fifos, cell}
    end
  end

  @doc """
  Enqueues a cell at the end of a PID's FIFO.
  """
  @spec enqueue(t(), pid(), TorCell.t()) :: t()
  def enqueue(fifos, pid, cell) do
    fifo = Map.get(fifos, pid)

    fifo =
      if fifo == nil do
        :queue.in(cell, :queue.new())
      else
        :queue.in(cell, fifo)
      end

    Map.put(fifos, pid, fifo)
  end

  @doc """
  Removes a a PID's FIFO entirely.
  """
  @spec kill(t(), pid()) :: t()
  def kill(fifos, pid) do
    Map.delete(fifos, pid)
  end
end
