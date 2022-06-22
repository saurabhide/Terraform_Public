package toproto5

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/internal/fwserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
)

// ReadDataSourceResponse returns the *tfprotov5.ReadDataSourceResponse
// equivalent of a *fwserver.ReadDataSourceResponse.
func ReadDataSourceResponse(ctx context.Context, fw *fwserver.ReadDataSourceResponse) *tfprotov5.ReadDataSourceResponse {
	if fw == nil {
		return nil
	}

	proto5 := &tfprotov5.ReadDataSourceResponse{
		Diagnostics: Diagnostics(fw.Diagnostics),
	}

	state, diags := State(ctx, fw.State)

	proto5.Diagnostics = append(proto5.Diagnostics, Diagnostics(diags)...)
	proto5.State = state

	return proto5
}
