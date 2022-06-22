package fwserver

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/internal/logging"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// ApplyResourceChangeRequest is the framework server request for the
// ApplyResourceChange RPC.
type ApplyResourceChangeRequest struct {
	Config         *tfsdk.Config
	PlannedPrivate []byte
	PlannedState   *tfsdk.Plan
	PriorState     *tfsdk.State
	ProviderMeta   *tfsdk.Config
	ResourceSchema tfsdk.Schema
	ResourceType   tfsdk.ResourceType
}

// ApplyResourceChangeResponse is the framework server response for the
// ApplyResourceChange RPC.
type ApplyResourceChangeResponse struct {
	Diagnostics diag.Diagnostics
	NewState    *tfsdk.State
	Private     []byte
}

// ApplyResourceChange implements the framework server ApplyResourceChange RPC.
func (s *Server) ApplyResourceChange(ctx context.Context, req *ApplyResourceChangeRequest, resp *ApplyResourceChangeResponse) {
	if req == nil {
		return
	}

	// If PriorState is missing/null, its a Create request.
	if req.PriorState == nil || req.PriorState.Raw.IsNull() {
		logging.FrameworkTrace(ctx, "ApplyResourceChange received no PriorState, running CreateResource")

		createReq := &CreateResourceRequest{
			Config:         req.Config,
			PlannedPrivate: req.PlannedPrivate,
			PlannedState:   req.PlannedState,
			ProviderMeta:   req.ProviderMeta,
			ResourceSchema: req.ResourceSchema,
			ResourceType:   req.ResourceType,
		}
		createResp := &CreateResourceResponse{}

		s.CreateResource(ctx, createReq, createResp)

		resp.Diagnostics = createResp.Diagnostics
		resp.NewState = createResp.NewState
		resp.Private = createResp.Private

		return
	}

	// If PlannedState is missing/null, its a Delete request.
	if req.PlannedState == nil || req.PlannedState.Raw.IsNull() {
		logging.FrameworkTrace(ctx, "ApplyResourceChange received no PlannedState, running DeleteResource")

		deleteReq := &DeleteResourceRequest{
			PlannedPrivate: req.PlannedPrivate,
			PriorState:     req.PriorState,
			ProviderMeta:   req.ProviderMeta,
			ResourceSchema: req.ResourceSchema,
			ResourceType:   req.ResourceType,
		}
		deleteResp := &DeleteResourceResponse{}

		s.DeleteResource(ctx, deleteReq, deleteResp)

		resp.Diagnostics = deleteResp.Diagnostics
		resp.NewState = deleteResp.NewState
		resp.Private = deleteResp.Private

		return
	}

	// Otherwise, assume its an Update request.
	logging.FrameworkTrace(ctx, "ApplyResourceChange running UpdateResource")

	updateReq := &UpdateResourceRequest{
		Config:         req.Config,
		PlannedPrivate: req.PlannedPrivate,
		PlannedState:   req.PlannedState,
		PriorState:     req.PriorState,
		ProviderMeta:   req.ProviderMeta,
		ResourceSchema: req.ResourceSchema,
		ResourceType:   req.ResourceType,
	}
	updateResp := &UpdateResourceResponse{}

	s.UpdateResource(ctx, updateReq, updateResp)

	resp.Diagnostics = updateResp.Diagnostics
	resp.NewState = updateResp.NewState
	resp.Private = updateResp.Private
}
