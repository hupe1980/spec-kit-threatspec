# Implementation Plan: RAG Assistant

**Branch**: `007-rag-assistant` | **Date**: 2026-09-20 | **Spec**: spec.md

## Summary

A FastAPI service with a retriever over a vector store, an LLM agent with one write-capable tool (ticket API), and a document ingestion endpoint for content authors.

## Technical Context

**Language/Version**: Python 3.12
**Primary Dependencies**: FastAPI, pgvector, hosted LLM API
**Storage**: PostgreSQL + pgvector
**Testing**: pytest

## Architecture

- `src/api/routes.py` — HTTP endpoints `/ask`, `/ingest`, `/tickets`
- `src/agent/prompt_builder.py` — assembles system prompt, retrieved context, user question
- `src/agent/tools.py` — ticket tool wrapper with confirmation gate
- `src/retrieval/retriever.py` — pgvector similarity search
- Third-party inference API over TLS
