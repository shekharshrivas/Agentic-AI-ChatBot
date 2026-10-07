"""
API routes for RAG operations.
"""

from fastapi import APIRouter, UploadFile, File, Header
from langchain_core.messages import HumanMessage, AIMessage

from src.memory.chat_history_mongo import ChatHistory
from src.models.query_request import QueryRequest
router = APIRouter()

_builder = None
_documents = None


def get_builder():
    """Lazily load the RAG graph builder."""
    global _builder
    if _builder is None:
        from src.rag.graph_builder import builder
        _builder = builder
    return _builder


def get_documents_uploader():
    """Lazily load the document uploader."""
    global _documents
    if _documents is None:
        from src.rag.document_upload import documents
        _documents = documents
    return _documents



@router.post("/rag/query")
async def rag_query(req: QueryRequest):
    """
    Process a RAG query and return the result.

    Args:
        req: The query request containing query text and session_id.

    Returns:
        The generated response from the RAG pipeline.
    """
    #chat_history=ChatInMemoryHistory.get_session_history(req.token)
    chat_history = ChatHistory.get_session_history(req.session_id)
    await chat_history.add_message(HumanMessage(content=req.query))

    # Fetch full history
    messages = await chat_history.get_messages()
    rag_builder = get_builder()
    result = rag_builder.invoke({
        "messages": messages
    })
    output_text = result["messages"][-1].content

    # Save assistant message
    await chat_history.add_message(AIMessage(content=output_text))

    return {"result": result["messages"][-1]}


@router.post("/rag/documents/upload")
async def upload_file(
    file: UploadFile = File(...),
    description: str = Header(..., alias="X-Description")
):
    """
    Upload a document for RAG processing.

    Args:
        file: The file to upload (PDF or TXT).
        description: Document description provided via header.

    Returns:
        Upload status.
    """
    uploader = get_documents_uploader()
    status_upload = uploader(description, file)
    return {"status": status_upload}


